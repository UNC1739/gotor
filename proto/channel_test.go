package proto

import (
	"bytes"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
)

func TestPickCircIDHighBit(t *testing.T) {
	used := map[uint32]struct{}{}
	for range 32 {
		id, err := PickCircID(used)
		if err != nil {
			t.Fatal(err)
		}
		if id&0x80000000 == 0 {
			t.Fatalf("high bit unset %#x", id)
		}
		if id == 0 {
			t.Fatal("zero")
		}
		if _, ok := used[id]; ok {
			t.Fatalf("duplicate %#x", id)
		}
		used[id] = struct{}{}
	}
}

func TestPickCircIDRNGFailure(t *testing.T) {
	old := randReader
	t.Cleanup(func() { randReader = old })
	randReader = bytes.NewReader(nil)
	if _, err := PickCircID(nil); err == nil {
		t.Fatal("expected rng error")
	}
}

func TestPickCircIDExhausted(t *testing.T) {
	old := randReader
	t.Cleanup(func() { randReader = old })
	raw := []byte{0x11, 0x22, 0x33, 0x44}
	randReader = bytes.NewReader(bytes.Repeat(raw, 64))
	id := binaryBE(raw) | 0x80000000
	used := map[uint32]struct{}{id: {}}
	if _, err := PickCircID(used); err == nil {
		t.Fatal("expected exhaustion")
	}
}

func TestBinaryBE(t *testing.T) {
	if binaryBE([]byte{0x80, 0x00, 0x00, 0x01}) != 0x80000001 {
		t.Fatal("be")
	}
}

func TestReadTruncatedCell(t *testing.T) {
	if _, err := cell.Read(bytes.NewReader([]byte{0, 0, 0, 0, cell.CmdRelay}), 4); err == nil {
		t.Fatal("truncated payload")
	}
}

func tlsPair(t *testing.T) (cli, srv *Channel) {
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
	cli = NewChannel(cliConn)
	srv = NewChannel(srvConn)
	cli.SetLinkVersion(4)
	srv.SetLinkVersion(4)
	t.Cleanup(func() {
		_ = cli.Close()
		_ = srv.Close()
	})
	return cli, srv
}

func TestChannelDeliversSubscribedCells(t *testing.T) {
	cli, srv := tlsPair(t)
	got := srv.Subscribe(0x80000001)
	srv.StartReadLoop()
	if err := cli.WriteCell(cell.Padding()); err != nil {
		t.Fatal(err)
	}
	if err := cli.WriteCell(cell.Vpadding([]byte{1, 2, 3})); err != nil {
		t.Fatal(err)
	}
	if err := cli.WriteCell(cell.Destroy(0x80000001, 6)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-got:
		if c == nil || c.Command != cell.CmdDestroy || c.CircID != 0x80000001 || c.Body[0] != 6 {
			t.Fatalf("%+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
	select {
	case <-got:
		t.Fatal("padding delivered")
	case <-time.After(50 * time.Millisecond):
	}
	if srv.RemoteAddr() == nil {
		t.Fatal("remote")
	}
	if len(cli.PeerTLSDigest()) == 0 {
		t.Fatal("peer cert")
	}
}

func TestChannelUnsubscribe(t *testing.T) {
	cli, srv := tlsPair(t)
	got := srv.Subscribe(0x80000002)
	srv.Unsubscribe(0x80000002)
	_, ok := <-got
	if ok {
		t.Fatal("unsubscribed chan open")
	}
	srv.StartReadLoop()
	if err := cli.WriteCell(cell.Destroy(0x80000002, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-srv.Closed():
		t.Fatal("closed early")
	case <-time.After(50 * time.Millisecond):
	}
}

func TestChannelCloseStopsReadLoop(t *testing.T) {
	cli, srv := tlsPair(t)
	srv.StartReadLoop()
	_ = cli.Close()
	select {
	case <-srv.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("not closed")
	}
}

func TestWriteReadVersions(t *testing.T) {
	cli, srv := tlsPair(t)
	if err := cli.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	vc, err := srv.ReadVersions()
	if err != nil {
		t.Fatal(err)
	}
	vs, err := cell.ParseVersions(vc.Body)
	if err != nil || len(vs) != 2 || vs[0] != 4 || vs[1] != 5 {
		t.Fatalf("%v %v", vs, err)
	}
}

func TestChannelErrOnTruncatedCell(t *testing.T) {
	cli, srv := tlsPair(t)
	srv.StartReadLoop()
	if _, err := cli.Conn.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	select {
	case <-srv.Closed():
	case <-time.After(2 * time.Second):
		t.Fatal("not closed")
	}
	if srv.Err() == nil {
		t.Fatal("expected read error")
	}
}

func TestChannelZeroCircFallback(t *testing.T) {
	cli, srv := tlsPair(t)
	zero := srv.Subscribe(0)
	srv.StartReadLoop()
	if err := cli.WriteCell(cell.Destroy(0x80000099, 11)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-zero:
		if c == nil || c.Command != cell.CmdDestroy || c.CircID != 0x80000099 {
			t.Fatalf("%+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestChannelZeroCircDropsWhenFull(t *testing.T) {
	cli, srv := tlsPair(t)
	_ = srv.Subscribe(0)
	srv.StartReadLoop()
	for i := 0; i < 70; i++ {
		if err := cli.WriteCell(cell.Destroy(0x80000000+uint32(i), 1)); err != nil {
			t.Fatal(err)
		}
	}
	if err := cli.WriteCell(cell.Destroy(0x80000001, 1)); err != nil {
		t.Fatal(err)
	}
}

func TestChannelIgnoresPadding(t *testing.T) {
	cli, srv := tlsPair(t)
	got := srv.Subscribe(0x80000001)
	srv.StartReadLoop()
	if err := cli.WriteCell(cell.Padding()); err != nil {
		t.Fatal(err)
	}
	if err := cli.WriteCell(cell.Vpadding([]byte{1, 2, 3})); err != nil {
		t.Fatal(err)
	}
	if err := cli.WriteCell(cell.Destroy(0x80000001, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case c := <-got:
		if c == nil || c.Command != cell.CmdDestroy {
			t.Fatalf("%+v", c)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestPeerTLSDigestNoCerts(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- []byte{1}
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}})
		got <- NewChannel(srv).PeerTLSDigest()
		_ = srv.Close()
	}()
	cli, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	select {
	case d := <-got:
		if d != nil {
			t.Fatal("expected no peer cert")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout")
	}
}

func TestChannelShutdownIdempotent(t *testing.T) {
	cli, srv := tlsPair(t)
	_ = cli
	srv.shutdown()
	srv.shutdown()
	select {
	case <-srv.Closed():
	default:
		t.Fatal("not closed")
	}
}
