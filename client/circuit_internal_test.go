package client

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
	"github.com/adam/gotor/crypto"
	"github.com/adam/gotor/directory"
	"github.com/adam/gotor/proto"
)

func TestWaitLinkCreated(t *testing.T) {
	inc := make(chan *cell.Cell, 2)
	circ := &Circuit{inc: inc}
	inc <- cell.Padding()
	inc <- cell.Created2(1, bytes.Repeat([]byte{9}, 64))
	got, err := circ.waitLink(cell.CmdCreated2, time.Second)
	if err != nil || got.Command != cell.CmdCreated2 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestWaitLinkDestroy(t *testing.T) {
	inc := make(chan *cell.Cell, 1)
	circ := &Circuit{inc: inc}
	inc <- cell.Destroy(1, 6)
	_, err := circ.waitLink(cell.CmdCreated2, time.Second)
	if err == nil {
		t.Fatal("expected DESTROY")
	}
}

func TestWaitLinkTimeout(t *testing.T) {
	circ := &Circuit{inc: make(chan *cell.Cell)}
	_, err := circ.waitLink(cell.CmdCreated2, 20*time.Millisecond)
	if err == nil {
		t.Fatal("expected timeout")
	}
}

func TestWaitLinkChannelClosed(t *testing.T) {
	inc := make(chan *cell.Cell)
	close(inc)
	circ := &Circuit{inc: inc}
	_, err := circ.waitLink(cell.CmdCreatedFast, time.Second)
	if err == nil {
		t.Fatal("expected closed")
	}
}

func TestCreditSendmeStreamWindow(t *testing.T) {
	circ := &Circuit{
		streams:  map[uint16]*Stream{},
		flowCond: sync.NewCond(new(sync.Mutex)),
	}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	st := &Stream{id: 1, circ: circ, pack: 0}
	circ.streams[1] = st
	circ.creditSendme(&cell.Relay{StreamID: 1})
	if st.pack != cell.StreamWindowInc {
		t.Fatalf("pack %d", st.pack)
	}
}

func TestCreditSendmeCircuitWindow(t *testing.T) {
	dig := bytes.Repeat([]byte{0xab}, 20)
	circ := &Circuit{circPack: 0, expectDig: [][]byte{dig}}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	circ.creditSendme(&cell.Relay{Data: cell.EncodeSendmeV1(dig)})
	if circ.circPack != cell.CircWindowInc || len(circ.expectDig) != 0 {
		t.Fatalf("pack=%d digs=%d", circ.circPack, len(circ.expectDig))
	}
}


func TestCreditSendmeKillsUnparseable(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	cli.StartReadLoop()
	circ := &Circuit{ch: cli, id: 1}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	circ.creditSendme(&cell.Relay{Data: []byte{1}})
	select {
	case <-cli.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("circuit not killed")
	}
}


func TestCreditSendmeKillsDigestMismatch(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	cli.StartReadLoop()
	circ := &Circuit{ch: cli, id: 1}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	circ.expectDig = [][]byte{bytes.Repeat([]byte{1}, 20)}
	circ.creditSendme(&cell.Relay{Data: cell.EncodeSendmeV1(bytes.Repeat([]byte{2}, 20))})
	select {
	case <-cli.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("circuit not killed")
	}
}


func clientTLSPair(t *testing.T) (cli, srv *proto.Channel) {
	t.Helper()
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	accepted := make(chan *tls.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		if err := s.Handshake(); err != nil {
			return
		}
		accepted <- s
	}()
	cliConn, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	srvConn := <-accepted
	cli = proto.NewChannel(cliConn)
	srv = proto.NewChannel(srvConn)
	cli.SetLinkVersion(4)
	srv.SetLinkVersion(4)
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestExtendNoIPv4(t *testing.T) {
	circ := &Circuit{}
	err := circ.extend(&directory.Relay{Nickname: "v6", Address: net.ParseIP("::1")})
	if err == nil {
		t.Fatal("expected no IPv4")
	}
}

func TestExtendUnexpectedCell(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	hop := dummyHop(t)
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{hop}, ctrl: make(chan *cell.Relay, 1)}
	circ.ctrl <- &cell.Relay{Command: cell.RelayTruncated, Data: []byte{1}}
	err := circ.extend(&directory.Relay{Nickname: "r", Address: net.ParseIP("127.0.0.1"), ORPort: 9001})
	if err == nil {
		t.Fatal("expected unexpected cell")
	}
}

func TestExtendBadHandshake(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	hop := dummyHop(t)
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{hop}, ctrl: make(chan *cell.Relay, 1)}
	circ.ctrl <- &cell.Relay{Command: cell.RelayExtended2, Data: cell.EncodeExtended2(make([]byte, 64))}
	err := circ.extend(&directory.Relay{Nickname: "r", Address: net.ParseIP("10.0.0.2"), ORPort: 9001})
	if err == nil {
		t.Fatal("expected ntor fail")
	}
}

func TestBuildCircuitDialFail(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	tcp := ln.Addr().(*net.TCPAddr)
	_ = ln.Close()
	c := &Client{}
	_, err = c.BuildCircuit([]*directory.Relay{{Address: tcp.IP, ORPort: uint16(tcp.Port)}})
	if err == nil {
		t.Fatal("expected dial fail")
	}
}

func TestBuildCircuitHandshakeFail(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}})
		_ = s.Handshake()
		_ = s.Close()
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	c := &Client{}
	_, err = c.BuildCircuit([]*directory.Relay{{Address: tcp.IP, ORPort: uint16(tcp.Port)}})
	if err == nil {
		t.Fatal("expected handshake fail")
	}
}

func TestStreamWriteAfterClose(t *testing.T) {
	circ := &Circuit{circPack: 0}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	s := &Stream{circ: circ, pack: 0}
	s.cond = sync.NewCond(&s.mu)
	s.closed.Store(true)
	if _, err := s.Write([]byte{1}); err == nil {
		t.Fatal("expected EOF")
	}
}

func dummyHop(t *testing.T) *crypto.Hop {
	t.Helper()
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i + 1)
		}
		return b
	}
	h, err := crypto.NewHop(&crypto.CircuitKeys{Df: fill(20), Db: fill(20), Kf: fill(16), Kb: fill(16), KH: fill(20)})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestCreateFirstHopDestroy(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	inc := make(chan *cell.Cell, 1)
	inc <- cell.Destroy(1, 2)
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	if err := circ.createFirstHop(&directory.Relay{}, true); err == nil {
		t.Fatal("expected DESTROY")
	}
}

func TestCreateFirstHopShortCreatedFast(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	inc := make(chan *cell.Cell, 1)
	inc <- &cell.Cell{Command: cell.CmdCreatedFast, Body: []byte{1}}
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	if err := circ.createFirstHop(&directory.Relay{}, true); err == nil {
		t.Fatal("expected short CREATED_FAST")
	}
}

func TestCreateFirstHopNtorDestroy(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	key, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inc := make(chan *cell.Cell, 1)
	inc <- cell.Destroy(1, 1)
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	g := &directory.Relay{NTorOnionKey: key.Public}
	if err := circ.createFirstHop(g, false); err == nil {
		t.Fatal("expected DESTROY")
	}
}

func TestCreateFirstHopShortCreated2(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	key, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inc := make(chan *cell.Cell, 1)
	inc <- &cell.Cell{Command: cell.CmdCreated2, Body: []byte{0}}
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	g := &directory.Relay{NTorOnionKey: key.Public}
	if err := circ.createFirstHop(g, false); err == nil {
		t.Fatal("expected short CREATED2")
	}
}

func TestHandleRelayDropUnrecognized(t *testing.T) {
	circ := &Circuit{hops: []*crypto.Hop{dummyHop(t)}}
	body := cell.EncodeRelay(cell.Relay{Command: cell.RelayDrop})
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: body})
}

func TestHandleRelayRecognizedDropAndData(t *testing.T) {
	ch, rh := pairedHop(t)
	circ := &Circuit{hops: []*crypto.Hop{ch}, streams: map[uint16]*Stream{}, ctrl: make(chan *cell.Relay, 1), circDel: cell.CircWindowStart}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	drop := cell.EncodeRelay(cell.Relay{Command: cell.RelayDrop})
	rh.SealBackward(drop)
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: drop})
	st := &Stream{id: 1, circ: circ, deliv: cell.StreamWindowStart}
	st.cond = sync.NewCond(&st.mu)
	circ.streams[1] = st
	data := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("hi")})
	rh.SealBackward(data)
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: data})
	if string(st.buf) != "hi" {
		t.Fatalf("buf=%q", st.buf)
	}
	ext := cell.EncodeRelay(cell.Relay{Command: cell.RelayExtended2, Data: []byte{0, 1}})
	rh.SealBackward(ext)
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: ext})
	select {
	case msg := <-circ.ctrl:
		if msg.Command != cell.RelayExtended2 {
			t.Fatalf("%+v", msg)
		}
	default:
		t.Fatal("expected ctrl EXTENDED2")
	}
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: []byte{1, 2, 3}})
}


func TestWaitConnectedEndAndConnected(t *testing.T) {
	circ := &Circuit{waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}}
	s := &Stream{id: 7, circ: circ}
	wait := make(chan *cell.Relay, 1)
	wait <- &cell.Relay{Command: cell.RelayEnd, Data: []byte{cell.EndReasonExitPolicy}}
	if _, err := circ.waitConnected(s, wait); err == nil {
		t.Fatal("expected END")
	}
	wait = make(chan *cell.Relay, 1)
	wait <- &cell.Relay{Command: cell.RelayEnd}
	if _, err := circ.waitConnected(s, wait); err == nil {
		t.Fatal("expected END misc")
	}
	wait = make(chan *cell.Relay, 1)
	wait <- &cell.Relay{Command: cell.RelayData}
	if _, err := circ.waitConnected(s, wait); err == nil {
		t.Fatal("expected not CONNECTED")
	}
	wait = make(chan *cell.Relay, 1)
	wait <- &cell.Relay{Command: cell.RelayConnected, Data: []byte{1, 2, 3, 4, 0, 0, 0, 0}}
	got, err := circ.waitConnected(s, wait)
	if err != nil || got != s || circ.streams[7] != s {
		t.Fatalf("%v %v", got, err)
	}
}


func TestHandleRelayDecodeErrorAndFullQueues(t *testing.T) {
	ch, rh := pairedHop(t)
	circ := &Circuit{hops: []*crypto.Hop{ch}, ctrl: make(chan *cell.Relay, 1), waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}}
	bad := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("x")})
	bad[9], bad[10] = 0x01, 0xf4
	rh.SealBackward(bad)
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: bad})
	ext := cell.EncodeRelay(cell.Relay{Command: cell.RelayExtended2, Data: []byte{1}})
	rh.SealBackward(ext)
	circ.ctrl <- &cell.Relay{Command: cell.RelayExtended2}
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: ext})
	w := make(chan *cell.Relay, 1)
	w <- &cell.Relay{Command: cell.RelayConnected}
	circ.waiters[3] = w
	conn := cell.EncodeRelay(cell.Relay{Command: cell.RelayConnected, StreamID: 3})
	rh.SealBackward(conn)
	circ.handleRelay(&cell.Cell{Command: cell.CmdRelay, Body: conn})
}

func TestWaitLinkRelayThenCreated(t *testing.T) {
	ch, rh := pairedHop(t)
	inc := make(chan *cell.Cell, 2)
	drop := cell.EncodeRelay(cell.Relay{Command: cell.RelayDrop})
	rh.SealBackward(drop)
	inc <- &cell.Cell{Command: cell.CmdRelay, Body: drop}
	inc <- cell.Created2(1, bytes.Repeat([]byte{9}, 64))
	circ := &Circuit{inc: inc, hops: []*crypto.Hop{ch}}
	got, err := circ.waitLink(cell.CmdCreated2, time.Second)
	if err != nil || got.Command != cell.CmdCreated2 {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestExtendShortExtended2(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, ctrl: make(chan *cell.Relay, 1)}
	circ.ctrl <- &cell.Relay{Command: cell.RelayExtended2, Data: []byte{0}}
	err := circ.extend(&directory.Relay{Nickname: "r", Address: net.ParseIP("10.0.0.2"), ORPort: 9001})
	if err == nil {
		t.Fatal("expected short EXTENDED2")
	}
}

func TestResolveTruncatedAnswer(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, nextSID: 1}
	errc := make(chan error, 1)
	go func() { _, err := circ.Resolve("h"); errc <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		circ.mu.Lock()
		if len(circ.waiters) > 0 {
			for _, w := range circ.waiters {
				w <- &cell.Relay{Command: cell.RelayResolved, Data: []byte{cell.ResolvedIPv4}}
			}
			circ.mu.Unlock()
			if err := <-errc; err == nil {
				t.Fatal("expected parse error")
			}
			return
		}
		circ.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no waiter")
}

func TestDialDirConnected(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}, nextSID: 0xffff}
	errc := make(chan error, 1)
	go func() { _, err := circ.DialDir(); errc <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		circ.mu.Lock()
		if len(circ.waiters) > 0 {
			if circ.nextSID != 1 {
				circ.mu.Unlock()
				t.Fatalf("nextSID=%d", circ.nextSID)
			}
			for _, w := range circ.waiters {
				w <- &cell.Relay{Command: cell.RelayConnected}
			}
			circ.mu.Unlock()
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			return
		}
		circ.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no waiter")
}

func TestStreamReadEOF(t *testing.T) {
	s := &Stream{}
	s.cond = sync.NewCond(&s.mu)
	s.closed.Store(true)
	n, err := s.Read(make([]byte, 8))
	if n != 0 || err == nil {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestDialDirWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}, nextSID: 1}
	if _, err := circ.DialDir(); err == nil {
		t.Fatal("expected write fail")
	}
}


func pairedHop(t *testing.T) (clientHop, relayHop *crypto.Hop) {
	t.Helper()
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = byte(i + 3)
		}
		return b
	}
	k := &crypto.CircuitKeys{Df: fill(20), Db: fill(20), Kf: fill(16), Kb: fill(16), KH: fill(20)}
	var err error
	clientHop, err = crypto.NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	relayHop, err = crypto.NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	return
}


func TestCreateFirstHopKHMismatch(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	inc := make(chan *cell.Cell, 1)
	inc <- cell.CreatedFast(1, bytes.Repeat([]byte{9}, 20), bytes.Repeat([]byte{8}, 20))
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	if err := circ.createFirstHop(&directory.Relay{}, true); err == nil {
		t.Fatal("expected KH mismatch")
	}
}

func TestCreateFirstHopNtorBadReply(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	key, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inc := make(chan *cell.Cell, 1)
	inc <- cell.Created2(1, make([]byte, 64))
	circ := &Circuit{ch: cli, id: 1, inc: inc}
	g := &directory.Relay{NTorOnionKey: key.Public}
	if err := circ.createFirstHop(g, false); err == nil {
		t.Fatal("expected ntor fail")
	}
}

func TestCreateFirstHopWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, id: 1, inc: make(chan *cell.Cell)}
	if err := circ.createFirstHop(&directory.Relay{}, true); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestResolveErrorAndEmpty(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, nextSID: 1}
	inject := func(msg *cell.Relay) error {
		errc := make(chan error, 1)
		go func() { _, err := circ.Resolve("host"); errc <- err }()
		deadline := time.Now().Add(2 * time.Second)
		for time.Now().Before(deadline) {
			circ.mu.Lock()
			if len(circ.waiters) > 0 {
				for _, w := range circ.waiters {
					w <- msg
				}
				circ.mu.Unlock()
				return <-errc
			}
			circ.mu.Unlock()
			time.Sleep(time.Millisecond)
		}
		t.Fatal("no waiter")
		return nil
	}
	if err := inject(&cell.Relay{Command: cell.RelayResolved, Data: cell.EncodeResolved([]cell.Resolved{{Type: cell.ResolvedErr, Value: []byte("x")}})}); err == nil {
		t.Fatal("expected resolve error")
	}
	if err := inject(&cell.Relay{Command: cell.RelayEnd}); err == nil {
		t.Fatal("expected not RESOLVED")
	}
	if err := inject(&cell.Relay{Command: cell.RelayResolved, Data: cell.EncodeResolved([]cell.Resolved{{Type: cell.ResolvedHostname, Value: []byte("n")}})}); err == nil {
		t.Fatal("expected no addresses")
	}
}

func TestCreateFirstHopNtorWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	key, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	circ := &Circuit{ch: cli, id: 1, inc: make(chan *cell.Cell)}
	g := &directory.Relay{NTorOnionKey: key.Public}
	if err := circ.createFirstHop(g, false); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestExtendWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}}
	if err := circ.extend(&directory.Relay{Nickname: "r", Address: net.ParseIP("10.0.0.2"), ORPort: 9001}); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestResolveWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, nextSID: 1}
	if _, err := circ.Resolve("x"); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestDialSIDWrapAndConnected(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}, nextSID: 0xffff}
	errc := make(chan error, 1)
	go func() { _, err := circ.Dial("example.com", 80); errc <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		circ.mu.Lock()
		if len(circ.waiters) > 0 {
			if circ.nextSID != 1 {
				circ.mu.Unlock()
				t.Fatalf("nextSID=%d", circ.nextSID)
			}
			for _, w := range circ.waiters {
				w <- &cell.Relay{Command: cell.RelayConnected, Data: []byte{127, 0, 0, 1, 0, 0, 0, 0}}
			}
			circ.mu.Unlock()
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			return
		}
		circ.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no waiter")
}

func TestDialWriteFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, streams: map[uint16]*Stream{}, nextSID: 1}
	if _, err := circ.Dial("example.com", 80); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestResolveIPv4AndIPv6(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, nextSID: 1}
	errc := make(chan struct {
		ips []net.IP
		err error
	}, 1)
	go func() {
		ips, err := circ.Resolve("dual.example")
		errc <- struct {
			ips []net.IP
			err error
		}{ips, err}
	}()
	v6 := make([]byte, 16)
	v6[15] = 1
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		circ.mu.Lock()
		if len(circ.waiters) > 0 {
			for _, w := range circ.waiters {
				w <- &cell.Relay{Command: cell.RelayResolved, Data: cell.EncodeResolved([]cell.Resolved{
					{Type: cell.ResolvedIPv4, Value: []byte{1, 2, 3, 4}, TTL: 60},
					{Type: cell.ResolvedIPv6, Value: v6, TTL: 60},
				})}
			}
			circ.mu.Unlock()
			got := <-errc
			if got.err != nil || len(got.ips) != 2 || got.ips[0].String() != "1.2.3.4" || got.ips[1][15] != 1 {
				t.Fatalf("%v %v", got.ips, got.err)
			}
			return
		}
		circ.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no waiter")
}

func TestStreamWriteSendFail(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	_ = cli.Close()
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, circPack: 100}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	s := &Stream{circ: circ, pack: 100}
	s.cond = sync.NewCond(&s.mu)
	if _, err := s.Write([]byte("hello")); err == nil {
		t.Fatal("expected write fail")
	}
}

func TestBuildCircuitCreateDestroyed(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	keys := proto.ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der, Advertise: [4]byte{127, 0, 0, 1}}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		s := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		ch := proto.NewChannel(s)
		if err := proto.HandshakeResponder(ch, keys); err != nil {
			return
		}
		got, err := ch.ReadCell()
		if err != nil {
			return
		}
		_ = ch.WriteCell(cell.Destroy(got.CircID, 2))
	}()
	tcp := ln.Addr().(*net.TCPAddr)
	cli := &Client{}
	_, err = cli.BuildCircuit([]*directory.Relay{{Address: tcp.IP, ORPort: uint16(tcp.Port)}})
	if err == nil {
		t.Fatal("expected CREATE DESTROY")
	}
}

func TestResolveSIDWrap(t *testing.T) {
	cli, srv := clientTLSPair(t)
	_ = srv
	circ := &Circuit{ch: cli, hops: []*crypto.Hop{dummyHop(t)}, waiters: map[uint16]chan *cell.Relay{}, nextSID: 0xffff}
	errc := make(chan error, 1)
	go func() { _, err := circ.Resolve("h"); errc <- err }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		circ.mu.Lock()
		if len(circ.waiters) > 0 {
			if circ.nextSID != 1 {
				circ.mu.Unlock()
				t.Fatalf("nextSID=%d", circ.nextSID)
			}
			for _, w := range circ.waiters {
				w <- &cell.Relay{Command: cell.RelayResolved, Data: cell.EncodeResolved([]cell.Resolved{{Type: cell.ResolvedIPv4, Value: []byte{127, 0, 0, 1}}})}
			}
			circ.mu.Unlock()
			if err := <-errc; err != nil {
				t.Fatal(err)
			}
			return
		}
		circ.mu.Unlock()
		time.Sleep(time.Millisecond)
	}
	t.Fatal("no waiter")
}

func TestNoteDeliverEmitsSendmeAtWindow(t *testing.T) {
	cli, srv := clientTLSPair(t)
	hop := dummyHop(t)
	circ := &Circuit{
		ch:      cli,
		hops:    []*crypto.Hop{hop},
		circDel: cell.CircWindowStart - cell.CircWindowInc + 1,
	}
	circ.flowCond = sync.NewCond(&circ.flowMu)
	st := &Stream{id: 4, circ: circ, deliv: cell.StreamWindowStart - cell.StreamWindowInc + 1}
	circ.noteDeliver(st)
	if st.deliv != cell.StreamWindowStart {
		t.Fatalf("stream deliv %d", st.deliv)
	}
	if circ.circDel != cell.CircWindowStart {
		t.Fatalf("circ deliv %d", circ.circDel)
	}
	deadline := time.Now().Add(2 * time.Second)
	n := 0
	for n < 2 && time.Now().Before(deadline) {
		_ = srv.Conn.SetDeadline(deadline)
		got, err := srv.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if got.Command == cell.CmdRelay || got.Command == cell.CmdRelayEarly {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("sendme cells %d", n)
	}
}








