package sim

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/adam/gotor/cell"
	gtcrypto "github.com/adam/gotor/crypto"
	"github.com/adam/gotor/proto"
)

type circKey struct {
	ch *proto.Channel
	id uint32
}

type exitStream struct {
	conn   net.Conn
	wrMu   sync.Mutex
	wrCond *sync.Cond
	wrBuf  [][]byte
	dead   bool
	once   sync.Once
	pack   int
	deliv  int
}

func (st *exitStream) close() {
	st.once.Do(func() {
		st.wrMu.Lock()
		st.dead = true
		st.wrCond.Broadcast()
		st.wrMu.Unlock()
		st.conn.Close()
	})
}

func (st *exitStream) enqueue(p []byte) {
	st.wrMu.Lock()
	if !st.dead {
		st.wrBuf = append(st.wrBuf, p)
		st.wrCond.Signal()
	}
	st.wrMu.Unlock()
}

func (st *exitStream) writeLoop() {
	for {
		st.wrMu.Lock()
		for len(st.wrBuf) == 0 && !st.dead {
			st.wrCond.Wait()
		}
		if len(st.wrBuf) == 0 {
			st.wrMu.Unlock()
			return
		}
		p := st.wrBuf[0]
		st.wrBuf = st.wrBuf[1:]
		st.wrMu.Unlock()
		if err := writeFull(st.conn, p); err != nil {
			return
		}
	}
}

type circuit struct {
	mu         sync.Mutex
	hop        *gtcrypto.Hop
	kh         []byte
	prev       *proto.Channel
	prevID     uint32
	next       *proto.Channel
	nextID     uint32
	extendWait chan *cell.Cell
	streams    map[uint16]*exitStream
	flowMu     sync.Mutex
	flowCond   *sync.Cond
	circPack   int
	circDel    int
	packSince  int
	expectDig  [][]byte
	peer       *circuit
}

type Relay struct {
	Keys    *RelayKeys
	DirAddr string
	log     *slog.Logger

	ln net.Listener

	mu       sync.Mutex
	inbound  map[circKey]*circuit
	outbound map[circKey]*circuit
	serving  map[*proto.Channel]bool
	usedIDs  map[circKey]struct{}
	intro    map[string]*circuit
	rend     map[string]*circuit
}

func newRelay(keys *RelayKeys, log *slog.Logger) *Relay {
	return &Relay{
		Keys:     keys,
		log:      log,
		inbound:  map[circKey]*circuit{},
		outbound: map[circKey]*circuit{},
		serving:  map[*proto.Channel]bool{},
		usedIDs:  map[circKey]struct{}{},
		intro:    map[string]*circuit{},
		rend:     map[string]*circuit{},
	}
}

func (r *Relay) listen(host string, port int) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	ln, err := tls.Listen("tcp4", addr, r.Keys.TLSConfig())
	if err != nil {
		return err
	}
	r.ln = ln
	ta := ln.Addr().(*net.TCPAddr)
	r.Keys.ORPort = uint16(ta.Port)
	r.Keys.Listen = ln.Addr().String()
	go r.acceptLoop()
	return nil
}

func (r *Relay) acceptLoop() {
	for {
		c, err := r.ln.Accept()
		if err != nil {
			return
		}
		go r.handleConn(c)
	}
}

func (r *Relay) handleConn(nc net.Conn) {
	tc, ok := nc.(*tls.Conn)
	if !ok {
		nc.Close()
		return
	}
	if err := tc.Handshake(); err != nil {
		nc.Close()
		return
	}
	ch := proto.NewChannel(tc)
	if err := proto.HandshakeResponder(ch, r.Keys.Responder()); err != nil {
		r.log.Debug("responder handshake failed", "relay", r.Keys.Nickname, "err", err)
		ch.Close()
		return
	}
	r.serveChannel(ch)
}

func (r *Relay) serveChannel(ch *proto.Channel) {
	defer r.dropChannel(ch)
	for {
		c, err := ch.ReadCell()
		if err != nil {
			return
		}
		r.handleCell(ch, c)
	}
}

func (r *Relay) handleCell(ch *proto.Channel, c *cell.Cell) {
	switch c.Command {
	case cell.CmdCreate2:
		r.onCreate2(ch, c)
	case cell.CmdCreateFast:
		r.onCreateFast(ch, c)
	case cell.CmdCreated2:
		r.onCreated2(ch, c)
	case cell.CmdRelay, cell.CmdRelayEarly:
		r.onRelay(ch, c)
	case cell.CmdDestroy:
		r.mu.Lock()
		_, fromNext := r.outbound[circKey{ch, c.CircID}]
		r.mu.Unlock()
		r.destroy(ch, c.CircID, fromNext)
	case cell.CmdPadding, cell.CmdVpadding:
	default:
		r.log.Debug("ignored cell", "cmd", c.Command)
	}
}

func (r *Relay) onCreate2(ch *proto.Channel, c *cell.Cell) {
	htype, hdata, err := cell.ParseCreate2(c.Body)
	if err != nil {
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
		return
	}
	var reply []byte
	var keys *gtcrypto.CircuitKeys
	switch htype {
	case gtcrypto.HTypeNtor:
		srv := &gtcrypto.NtorServer{ID: r.Keys.Identity, Key: r.Keys.NTor}
		reply, keys, err = srv.Reply(rand.Reader, hdata)
	case gtcrypto.HTypeNtorV3:
		var id [32]byte
		if len(r.Keys.EdIDPub) != 32 {
			_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
			return
		}
		copy(id[:], r.Keys.EdIDPub)
		srv := &gtcrypto.NtorV3Server{ID: id, Key: r.Keys.NTor}
		reply, keys, _, err = srv.Reply(rand.Reader, hdata, nil, []byte(gtcrypto.NtorV3CircuitVerify))
	default:
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
		return
	}
	if err != nil {
		r.log.Debug("create2 failed", "relay", r.Keys.Nickname, "htype", htype, "err", err)
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
		return
	}
	if _, err := r.installHop(ch, c.CircID, keys); err != nil {
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyInternal))
		return
	}
	if err := ch.WriteCell(cell.Created2(c.CircID, reply)); err != nil {
		r.destroy(ch, c.CircID, false)
	}
}

func (r *Relay) installHop(ch *proto.Channel, circID uint32, keys *gtcrypto.CircuitKeys) (*circuit, error) {
	hop, err := gtcrypto.NewHop(keys)
	if err != nil {
		return nil, err
	}
	ci := &circuit{
		hop:      hop,
		kh:       append([]byte(nil), keys.KH...),
		prev:     ch,
		prevID:   circID,
		streams:  map[uint16]*exitStream{},
		circPack: cell.CircWindowStart,
		circDel:  cell.CircWindowStart,
	}
	ci.flowCond = sync.NewCond(&ci.flowMu)
	r.mu.Lock()
	r.inbound[circKey{ch, circID}] = ci
	r.mu.Unlock()
	return ci, nil
}

func (r *Relay) onCreateFast(ch *proto.Channel, c *cell.Cell) {
	x, err := cell.ParseCreateFast(c.Body)
	if err != nil {
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
		return
	}
	y, kh, keys, err := gtcrypto.CreateFastReply(rand.Reader, x)
	if err != nil {
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyProtocol))
		return
	}
	if _, err := r.installHop(ch, c.CircID, keys); err != nil {
		_ = ch.WriteCell(cell.Destroy(c.CircID, cell.DestroyInternal))
		return
	}
	if err := ch.WriteCell(cell.CreatedFast(c.CircID, y, kh)); err != nil {
		r.destroy(ch, c.CircID, false)
	}
}

func (r *Relay) onCreated2(ch *proto.Channel, c *cell.Cell) {
	r.mu.Lock()
	ci := r.outbound[circKey{ch, c.CircID}]
	r.mu.Unlock()
	if ci == nil || ci.extendWait == nil {
		return
	}
	select {
	case ci.extendWait <- c:
	default:
	}
}

func (r *Relay) onRelay(ch *proto.Channel, c *cell.Cell) {
	r.mu.Lock()
	in := r.inbound[circKey{ch, c.CircID}]
	out := r.outbound[circKey{ch, c.CircID}]
	r.mu.Unlock()
	body := make([]byte, cell.BodyLen)
	copy(body, c.Body)
	if in != nil {
		in.mu.Lock()
		in.hop.DecryptForward(body)
		rec := in.hop.RecognizeForward(body)
		next := in.next
		nextID := in.nextID
		peer := in.peer
		in.mu.Unlock()
		if rec {
			msg, err := cell.DecodeRelay(body)
			if err != nil {
				return
			}
			r.handleRecognized(in, msg)
			return
		}
		if next != nil {
			_ = next.WriteCell(&cell.Cell{CircID: nextID, Command: cell.CmdRelay, Body: body})
			return
		}
		if peer != nil && peer.prev != nil {
			peer.mu.Lock()
			peer.hop.EncryptBackward(body)
			prev, id := peer.prev, peer.prevID
			peer.mu.Unlock()
			_ = prev.WriteCell(&cell.Cell{CircID: id, Command: cell.CmdRelay, Body: body})
		}
		return
	}
	if out != nil && out.prev != nil {
		out.mu.Lock()
		out.hop.EncryptBackward(body)
		out.mu.Unlock()
		_ = out.prev.WriteCell(&cell.Cell{CircID: out.prevID, Command: cell.CmdRelay, Body: body})
	}
}

func (r *Relay) handleRecognized(ci *circuit, msg *cell.Relay) {
	switch msg.Command {
	case cell.RelayExtend2:
		go r.doExtend(ci, msg)
	case cell.RelayBegin:
		go r.doBegin(ci, msg)
	case cell.RelayBeginDir:
		go r.doBeginDir(ci, msg)
	case cell.RelayResolve:
		go r.doResolve(ci, msg)
	case cell.RelayEstablishIntro:
		r.doEstablishIntro(ci, msg)
	case cell.RelayIntroduce1:
		r.doIntroduce1(ci, msg)
	case cell.RelayEstablishRendezvous:
		r.doEstablishRendezvous(ci, msg)
	case cell.RelayRendezvous1:
		r.doRendezvous1(ci, msg)
	case cell.RelayData:
		r.mu.Lock()
		st := ci.streams[msg.StreamID]
		r.mu.Unlock()
		if st != nil {
			r.noteDeliver(ci, st, msg.StreamID)
			st.enqueue(append([]byte(nil), msg.Data...))
		}
	case cell.RelayEnd:
		r.closeStream(ci, msg.StreamID)
	case cell.RelaySendme:
		r.creditSendme(ci, msg.StreamID, msg.Data)
	case cell.RelayDrop:
	case cell.RelayPaddingNegotiate:
		r.doPaddingNegotiate(ci, msg)
	default:
		r.log.Debug("unhandled relay cmd", "cmd", msg.Command, "relay", r.Keys.Nickname)
	}
}

func (r *Relay) doEstablishIntro(ci *circuit, msg *cell.Relay) {
	authKey, mac, signed, sig, err := cell.ParseEstablishIntro(msg.Data)
	if err != nil {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	want := gtcrypto.IntroHandshakeMAC(ci.kh, cell.EstablishIntroMACPrefix(authKey))
	if !hmac.Equal(mac, want) {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	msgToSign := append([]byte("Tor establish-intro cell v1"), signed...)
	if !ed25519.Verify(authKey, msgToSign, sig) {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	r.mu.Lock()
	r.intro[string(authKey)] = ci
	r.mu.Unlock()
	r.sendBack(ci, cell.RelayIntroEstablished, 0, []byte{0})
}

func (r *Relay) doPaddingNegotiate(ci *circuit, msg *cell.Relay) {
	n, err := cell.ParsePaddingNegotiate(msg.Data)
	if err != nil {
		return
	}
	r.sendBack(ci, cell.RelayPaddingNegotiated, 0, cell.EncodePaddingNegotiated(n.Command, cell.CircPadResponseERR, n.MachineType, n.MachineCtr))
}

func (r *Relay) doIntroduce1(ci *circuit, msg *cell.Relay) {
	authKey, _, err := cell.ParseIntroduce1(msg.Data)
	if err != nil {
		r.sendBack(ci, cell.RelayIntroduceAck, 0, cell.EncodeIntroduceAck(2))
		return
	}
	r.mu.Lock()
	svc := r.intro[string(authKey)]
	r.mu.Unlock()
	if svc == nil {
		r.sendBack(ci, cell.RelayIntroduceAck, 0, cell.EncodeIntroduceAck(1))
		return
	}
	r.sendBack(svc, cell.RelayIntroduce2, 0, msg.Data)
	r.sendBack(ci, cell.RelayIntroduceAck, 0, cell.EncodeIntroduceAck(0))
}

func (r *Relay) doEstablishRendezvous(ci *circuit, msg *cell.Relay) {
	if len(msg.Data) < 20 {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	cookie := string(msg.Data[:20])
	r.mu.Lock()
	if _, ok := r.rend[cookie]; ok {
		r.mu.Unlock()
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	r.rend[cookie] = ci
	r.mu.Unlock()
	r.sendBack(ci, cell.RelayRendezvousEstablished, 0, nil)
}

func (r *Relay) doRendezvous1(ci *circuit, msg *cell.Relay) {
	if len(msg.Data) < 20 {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	cookie := string(msg.Data[:20])
	hsinfo := append([]byte(nil), msg.Data[20:]...)
	r.mu.Lock()
	cli := r.rend[cookie]
	if cli == nil {
		r.mu.Unlock()
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyProtocol))
		return
	}
	delete(r.rend, cookie)
	cli.peer = ci
	ci.peer = cli
	r.mu.Unlock()
	r.sendBack(cli, cell.RelayRendezvous2, 0, hsinfo)
}

func (r *Relay) doExtend(ci *circuit, msg *cell.Relay) {
	fail := func(reason byte) {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, reason))
	}
	ext, err := cell.ParseExtend2(msg.Data)
	if err != nil {
		fail(cell.DestroyProtocol)
		return
	}
	ip, port, ok := ext.IPv4Port()
	if !ok {
		fail(cell.DestroyProtocol)
		return
	}
	addr := net.JoinHostPort(net.IP(ip[:]).String(), fmt.Sprintf("%d", port))
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		r.log.Debug("extend dial failed", "addr", addr, "err", err)
		fail(cell.DestroyConnectFailed)
		return
	}
	ch := proto.NewChannel(conn)
	var expect ed25519ID
	for _, s := range ext.Specs {
		if s.Type == cell.LSEd25519 && len(s.Data) == 32 {
			expect = s.Data
		}
	}
	if _, err := proto.HandshakeInitiatorRelay(ch, expect, r.Keys.Initiator()); err != nil {
		r.log.Debug("extend handshake failed", "err", err)
		ch.Close()
		reason := byte(cell.DestroyConnectFailed)
		if errors.Is(err, proto.ErrIdentityMismatch) {
			reason = cell.DestroyORIdentity
		}
		fail(reason)
		return
	}
	nextID, err := proto.PickCircID(nil)
	if err != nil {
		ch.Close()
		fail(cell.DestroyResourceLimit)
		return
	}
	ci.next = ch
	ci.nextID = nextID
	ci.extendWait = make(chan *cell.Cell, 1)
	r.mu.Lock()
	r.outbound[circKey{ch, nextID}] = ci
	r.mu.Unlock()
	r.ensureServe(ch)
	if err := ch.WriteCell(cell.Create2(nextID, ext.HType, ext.HData)); err != nil {
		fail(cell.DestroyConnectFailed)
		return
	}
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	select {
	case created := <-ci.extendWait:
		hdata, err := cell.ParseCreated2(created.Body)
		if err != nil {
			fail(cell.DestroyProtocol)
			return
		}
		body := cell.EncodeRelay(cell.Relay{Command: cell.RelayExtended2, Data: cell.EncodeExtended2(hdata)})
		ci.mu.Lock()
		ci.hop.SealBackward(body)
		ci.mu.Unlock()
		_ = ci.prev.WriteCell(&cell.Cell{CircID: ci.prevID, Command: cell.CmdRelay, Body: body})
	case <-t.C:
		fail(cell.DestroyTimeout)
	}
}

type ed25519ID = []byte

func (r *Relay) ensureServe(ch *proto.Channel) {
	r.mu.Lock()
	if r.serving[ch] {
		r.mu.Unlock()
		return
	}
	r.serving[ch] = true
	r.mu.Unlock()
	go r.serveChannel(ch)
}

func (r *Relay) doResolve(ci *circuit, msg *cell.Relay) {
	host := cell.ParseResolve(msg.Data)
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		r.sendBack(ci, cell.RelayResolved, msg.StreamID, cell.EncodeResolved([]cell.Resolved{{
			Type:  cell.ResolvedErr,
			Value: []byte("Error resolving hostname"),
			TTL:   0,
		}}))
		return
	}
	var ans []cell.Resolved
	for _, ip := range addrs {
		if v4 := ip.To4(); v4 != nil {
			ans = append([]cell.Resolved{{Type: cell.ResolvedIPv4, Value: append([]byte(nil), v4...), TTL: 60}}, ans...)
		}
	}
	for _, ip := range addrs {
		if v4 := ip.To4(); v4 == nil {
			v6 := ip.To16()
			if v6 != nil {
				ans = append(ans, cell.Resolved{Type: cell.ResolvedIPv6, Value: append([]byte(nil), v6...), TTL: 60})
			}
		}
	}
	r.sendBack(ci, cell.RelayResolved, msg.StreamID, cell.EncodeResolved(ans))
}

func (r *Relay) doBegin(ci *circuit, msg *cell.Relay) {
	sendEnd := func(reason byte) {
		r.sendBack(ci, cell.RelayEnd, msg.StreamID, []byte{reason})
	}
	host, port, flags, err := cell.ParseBegin(msg.Data)
	if err != nil {
		sendEnd(cell.EndReasonMisc)
		return
	}
	addrs, err := net.LookupIP(host)
	if err != nil || len(addrs) == 0 {
		sendEnd(cell.EndReasonResolveFailed)
		return
	}
	ip := cell.SelectBeginAddr(addrs, flags)
	if ip == nil {
		sendEnd(cell.EndReasonResolveFailed)
		return
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), strconv.Itoa(int(port))), 10*time.Second)
	if err != nil {
		r.log.Debug("exit dial failed", "host", host, "port", port, "err", err)
		sendEnd(cell.EndReasonConnectRefused)
		return
	}
	r.spliceExit(ci, msg, conn, make([]byte, 8))
}

func (r *Relay) doBeginDir(ci *circuit, msg *cell.Relay) {
	if r.DirAddr == "" {
		r.sendBack(ci, cell.RelayEnd, msg.StreamID, []byte{cell.EndReasonNotDirectory})
		return
	}
	conn, err := net.DialTimeout("tcp", r.DirAddr, 10*time.Second)
	if err != nil {
		r.sendBack(ci, cell.RelayEnd, msg.StreamID, []byte{cell.EndReasonNotDirectory})
		return
	}
	r.spliceExit(ci, msg, conn, nil)
}

func (r *Relay) spliceExit(ci *circuit, msg *cell.Relay, conn net.Conn, connected []byte) {
	st := &exitStream{conn: conn, pack: cell.StreamWindowStart, deliv: cell.StreamWindowStart}
	st.wrCond = sync.NewCond(&st.wrMu)
	r.mu.Lock()
	ci.streams[msg.StreamID] = st
	r.mu.Unlock()
	go st.writeLoop()
	r.sendBack(ci, cell.RelayConnected, msg.StreamID, connected)
	go func() {
		buf := make([]byte, cell.MaxRelayData)
		for {
			n, err := conn.Read(buf)
			if n > 0 {
				if !ci.takePack(st) {
					break
				}
				r.sendBack(ci, cell.RelayData, msg.StreamID, buf[:n])
			}
			if err != nil {
				r.sendBack(ci, cell.RelayEnd, msg.StreamID, []byte{cell.EndReasonDone})
				r.closeStream(ci, msg.StreamID)
				return
			}
		}
	}()
}

func (ci *circuit) takePack(st *exitStream) bool {
	ci.flowMu.Lock()
	defer ci.flowMu.Unlock()
	for ci.circPack <= 0 || st.pack <= 0 {
		ci.flowCond.Wait()
	}
	ci.circPack--
	st.pack--
	return true
}

func (r *Relay) creditSendme(ci *circuit, sid uint16, data []byte) {
	if sid != 0 {
		ci.flowMu.Lock()
		r.mu.Lock()
		st := ci.streams[sid]
		r.mu.Unlock()
		if st != nil {
			st.pack += cell.StreamWindowInc
		}
		ci.flowCond.Broadcast()
		ci.flowMu.Unlock()
		return
	}
	ver, dig, err := cell.ParseSendme(data)
	if err != nil || ver != cell.SendmeV1 || len(dig) < 20 {
		r.destroy(ci.prev, ci.prevID, false)
		return
	}
	ci.flowMu.Lock()
	if len(ci.expectDig) == 0 || !bytes.Equal(ci.expectDig[0], dig) {
		ci.flowMu.Unlock()
		r.destroy(ci.prev, ci.prevID, false)
		return
	}
	ci.expectDig = ci.expectDig[1:]
	ci.circPack += cell.CircWindowInc
	ci.flowCond.Broadcast()
	ci.flowMu.Unlock()
}

func (r *Relay) noteDeliver(ci *circuit, st *exitStream, sid uint16) {
	ci.mu.Lock()
	dig := append([]byte(nil), ci.hop.ForwardDigest()...)
	ci.mu.Unlock()
	ci.flowMu.Lock()
	ci.circDel--
	st.deliv--
	circSM := cell.NeedSendme(ci.circDel, cell.CircWindowStart, cell.CircWindowInc)
	strSM := cell.NeedSendme(st.deliv, cell.StreamWindowStart, cell.StreamWindowInc)
	if circSM {
		ci.circDel += cell.CircWindowInc
	}
	if strSM {
		st.deliv += cell.StreamWindowInc
	}
	ci.flowMu.Unlock()
	if circSM {
		r.sendBack(ci, cell.RelaySendme, 0, cell.EncodeSendmeV1(dig))
	}
	if strSM {
		r.sendBack(ci, cell.RelaySendme, sid, nil)
	}
}

func (r *Relay) sendBack(ci *circuit, cmd byte, sid uint16, data []byte) {
	body := cell.EncodeRelay(cell.Relay{Command: cmd, StreamID: sid, Data: data})
	ci.mu.Lock()
	ci.hop.SealBackward(body)
	var rem []byte
	if cmd == cell.RelayData {
		ci.packSince++
		if ci.packSince == cell.CircWindowInc {
			ci.packSince = 0
			rem = append([]byte(nil), ci.hop.BackwardDigest()...)
		}
	}
	if rem != nil {
		ci.flowMu.Lock()
		ci.expectDig = append(ci.expectDig, rem)
		ci.flowMu.Unlock()
	}
	_ = ci.prev.WriteCell(&cell.Cell{CircID: ci.prevID, Command: cell.CmdRelay, Body: body})
	ci.mu.Unlock()
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if n > 0 {
			p = p[n:]
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Relay) closeStream(ci *circuit, id uint16) {
	r.mu.Lock()
	st := ci.streams[id]
	delete(ci.streams, id)
	r.mu.Unlock()
	if st != nil {
		st.close()
	}
}

func (r *Relay) destroy(ch *proto.Channel, id uint32, fromNext bool) {
	r.mu.Lock()
	in := r.inbound[circKey{ch, id}]
	out := r.outbound[circKey{ch, id}]
	delete(r.inbound, circKey{ch, id})
	delete(r.outbound, circKey{ch, id})
	r.mu.Unlock()
	ci := in
	if ci == nil {
		ci = out
	}
	if ci == nil {
		return
	}
	for sid := range ci.streams {
		r.closeStream(ci, sid)
	}
	if ci.next != nil && !fromNext {
		_ = ci.next.WriteCell(cell.Destroy(ci.nextID, cell.DestroyDestroyed))
	}
	if ci.prev != nil && fromNext {
		_ = ci.prev.WriteCell(cell.Destroy(ci.prevID, cell.DestroyDestroyed))
	}
}

func (r *Relay) dropChannel(ch *proto.Channel) {
	r.mu.Lock()
	var ids []circKey
	for k := range r.inbound {
		if k.ch == ch {
			ids = append(ids, k)
		}
	}
	for k := range r.outbound {
		if k.ch == ch {
			ids = append(ids, k)
		}
	}
	delete(r.serving, ch)
	r.mu.Unlock()
	for _, k := range ids {
		r.destroy(k.ch, k.id, false)
	}
	_ = ch.Close()
}

func (r *Relay) Close() {
	if r.ln != nil {
		_ = r.ln.Close()
	}
}
