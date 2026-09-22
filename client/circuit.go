package client

import (
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/crypto"
	"github.com/adam/gotor/directory"
	"github.com/adam/gotor/proto"
)

type Circuit struct {
	ch     *proto.Channel
	id     uint32
	hops   []*crypto.Hop
	relays []*directory.Relay
	inc    <-chan *cell.Cell

	mu       sync.Mutex
	cryptoMu sync.Mutex
	flowMu   sync.Mutex
	flowCond *sync.Cond
	circPack   int
	circDel    int
	packSince  int
	expectDig  [][]byte
	streams    map[uint16]*Stream
	nextSID  uint16
	waiters  map[uint16]chan *cell.Relay
	ctrl     chan *cell.Relay
}

func (c *Client) BuildCircuit(relays []*directory.Relay) (*Circuit, error) {
	if len(relays) < 1 {
		return nil, fmt.Errorf("need at least one relay")
	}
	guard := relays[0]
	addr := net.JoinHostPort(guard.Address.String(), fmt.Sprintf("%d", guard.ORPort))
	tlsCfg := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", addr, tlsCfg)
	if err != nil {
		return nil, fmt.Errorf("dial guard: %w", err)
	}
	ch := proto.NewChannel(conn)
	if _, err := proto.HandshakeInitiator(ch, guard.Ed25519ID); err != nil {
		conn.Close()
		return nil, fmt.Errorf("handshake: %w", err)
	}
	circID, err := proto.PickCircID(nil)
	if err != nil {
		conn.Close()
		return nil, err
	}
	inc := ch.Subscribe(circID)
	ch.StartReadLoop()
	circ := &Circuit{
		ch:      ch,
		id:      circID,
		inc:     inc,
		streams: map[uint16]*Stream{},
		nextSID: 1,
		waiters:  map[uint16]chan *cell.Relay{},
		ctrl:     make(chan *cell.Relay, 8),
		relays:   relays,
		circPack: cell.CircWindowStart,
		circDel:  cell.CircWindowStart,
	}
	circ.flowCond = sync.NewCond(&circ.flowMu)

	hs, st, err := crypto.NtorClientHandshake(rand.Reader, guard.Identity, guard.NTorOnionKey)
	if err != nil {
		ch.Close()
		return nil, err
	}
	if err := ch.WriteCell(cell.Create2(circID, crypto.HTypeNtor, hs)); err != nil {
		ch.Close()
		return nil, err
	}
	created, err := circ.waitLink(cell.CmdCreated2, 10*time.Second)
	if err != nil {
		ch.Close()
		return nil, err
	}
	hdata, err := cell.ParseCreated2(created.Body)
	if err != nil {
		ch.Close()
		return nil, err
	}
	keys, err := st.Finish(hdata)
	if err != nil {
		ch.Close()
		return nil, err
	}
	hop, err := crypto.NewHop(keys)
	if err != nil {
		ch.Close()
		return nil, err
	}
	circ.hops = append(circ.hops, hop)
	go circ.dispatch()

	for i := 1; i < len(relays); i++ {
		if err := circ.extend(relays[i]); err != nil {
			ch.Close()
			return nil, fmt.Errorf("extend hop %d: %w", i, err)
		}
	}
	return circ, nil
}

func (circ *Circuit) waitLink(cmd byte, d time.Duration) (*cell.Cell, error) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case c, ok := <-circ.inc:
			if !ok {
				return nil, fmt.Errorf("channel closed")
			}
			if c.Command == cmd {
				return c, nil
			}
			if c.Command == cell.CmdDestroy {
				reason := byte(0)
				if len(c.Body) > 0 {
					reason = c.Body[0]
				}
				return nil, fmt.Errorf("DESTROY reason=%d", reason)
			}
			if c.Command == cell.CmdRelay || c.Command == cell.CmdRelayEarly {
				circ.handleRelay(c)
			}
		case <-t.C:
			return nil, fmt.Errorf("timeout waiting for cmd %d", cmd)
		}
	}
}

func (circ *Circuit) dispatch() {
	for c := range circ.inc {
		if c.Command == cell.CmdRelay || c.Command == cell.CmdRelayEarly {
			circ.handleRelay(c)
		}
	}
}

func (circ *Circuit) handleRelay(c *cell.Cell) {
	body := append([]byte(nil), c.Body...)
	if len(body) < cell.BodyLen {
		pad := make([]byte, cell.BodyLen)
		copy(pad, body)
		body = pad
	}
	circ.cryptoMu.Lock()
	_, ok := crypto.OnionDecrypt(circ.hops, body)
	circ.cryptoMu.Unlock()
	if !ok {
		return
	}
	msg, err := cell.DecodeRelay(body)
	if err != nil {
		return
	}
	if msg.Command == cell.RelaySendme {
		circ.creditSendme(msg)
		return
	}
	if msg.StreamID == 0 {
		select {
		case circ.ctrl <- msg:
		default:
		}
		return
	}
	circ.mu.Lock()
	w := circ.waiters[msg.StreamID]
	st := circ.streams[msg.StreamID]
	circ.mu.Unlock()
	if msg.Command == cell.RelayData && st != nil {
		circ.noteDeliver(st)
	}
	if st != nil {
		st.deliver(msg)
	}
	if w != nil {
		select {
		case w <- msg:
		default:
		}
	}
}

func (circ *Circuit) takePackage(s *Stream) error {
	circ.flowMu.Lock()
	defer circ.flowMu.Unlock()
	for circ.circPack <= 0 || s.pack <= 0 {
		if s.closed.Load() {
			return io.EOF
		}
		circ.flowCond.Wait()
	}
	circ.circPack--
	s.pack--
	return nil
}

func (circ *Circuit) creditSendme(msg *cell.Relay) {
	if msg.StreamID != 0 {
		circ.flowMu.Lock()
		circ.mu.Lock()
		st := circ.streams[msg.StreamID]
		circ.mu.Unlock()
		if st != nil {
			st.pack += cell.StreamWindowInc
		}
		circ.flowCond.Broadcast()
		circ.flowMu.Unlock()
		return
	}
	ver, dig, err := cell.ParseSendme(msg.Data)
	if err != nil || ver != cell.SendmeV1 || len(dig) < 20 {
		circ.kill()
		return
	}
	circ.flowMu.Lock()
	if len(circ.expectDig) == 0 || !bytes.Equal(circ.expectDig[0], dig) {
		circ.flowMu.Unlock()
		circ.kill()
		return
	}
	circ.expectDig = circ.expectDig[1:]
	circ.circPack += cell.CircWindowInc
	circ.flowCond.Broadcast()
	circ.flowMu.Unlock()
}

func (circ *Circuit) noteDeliver(s *Stream) {
	circ.cryptoMu.Lock()
	dig := append([]byte(nil), circ.hops[len(circ.hops)-1].BackwardDigest()...)
	circ.cryptoMu.Unlock()
	circ.flowMu.Lock()
	circ.circDel--
	s.deliv--
	circSM := cell.NeedSendme(circ.circDel, cell.CircWindowStart, cell.CircWindowInc)
	strSM := cell.NeedSendme(s.deliv, cell.StreamWindowStart, cell.StreamWindowInc)
	if circSM {
		circ.circDel += cell.CircWindowInc
	}
	if strSM {
		s.deliv += cell.StreamWindowInc
	}
	sid := s.id
	circ.flowMu.Unlock()
	go func() {
		if circSM {
			_ = circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{Command: cell.RelaySendme, Data: cell.EncodeSendmeV1(dig)})
		}
		if strSM {
			_ = circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{Command: cell.RelaySendme, StreamID: sid})
		}
	}()
}

func (circ *Circuit) kill() {
	circ.flowMu.Lock()
	circ.flowCond.Broadcast()
	circ.flowMu.Unlock()
	_ = circ.ch.WriteCell(cell.Destroy(circ.id, 1))
	_ = circ.ch.Close()
}

func (circ *Circuit) extend(r *directory.Relay) error {
	hs, st, err := crypto.NtorClientHandshake(rand.Reader, r.Identity, r.NTorOnionKey)
	if err != nil {
		return err
	}
	var ipv4 [4]byte
	ip4 := r.Address.To4()
	if ip4 == nil {
		return fmt.Errorf("relay %s has no IPv4", r.Nickname)
	}
	copy(ipv4[:], ip4)
	payload := cell.EncodeExtend2(ipv4, r.ORPort, r.Identity, r.Ed25519ID, crypto.HTypeNtor, hs)
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelayEarly, cell.Relay{
		Command: cell.RelayExtend2,
		Data:    payload,
	}); err != nil {
		return err
	}
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	select {
	case msg := <-circ.ctrl:
		if msg.Command != cell.RelayExtended2 {
			return fmt.Errorf("expected EXTENDED2, got %d", msg.Command)
		}
		hdata, err := cell.ParseExtended2(msg.Data)
		if err != nil {
			return err
		}
		keys, err := st.Finish(hdata)
		if err != nil {
			return err
		}
		hop, err := crypto.NewHop(keys)
		if err != nil {
			return err
		}
		circ.hops = append(circ.hops, hop)
		return nil
	case <-t.C:
		return fmt.Errorf("timeout waiting for EXTENDED2")
	}
}

func (circ *Circuit) sendRelay(dest int, linkCmd byte, r cell.Relay) error {
	body := cell.EncodeRelay(r)
	circ.cryptoMu.Lock()
	defer circ.cryptoMu.Unlock()
	crypto.OnionEncrypt(circ.hops, dest, body)
	if r.Command == cell.RelayData {
		circ.packSince++
		if circ.packSince == cell.CircWindowInc {
			circ.packSince = 0
			d := append([]byte(nil), circ.hops[dest].ForwardDigest()...)
			circ.flowMu.Lock()
			circ.expectDig = append(circ.expectDig, d)
			circ.flowMu.Unlock()
		}
	}
	return circ.ch.WriteCell(&cell.Cell{CircID: circ.id, Command: linkCmd, Body: body})
}

func (circ *Circuit) Close() error {
	_ = circ.ch.WriteCell(cell.Destroy(circ.id, 0))
	return circ.ch.Close()
}
