package cell

import (
	"bytes"
	"net"
	"testing"
)

func TestFixedRoundTrip(t *testing.T) {
	c := Create2(0x80000001, 2, bytes.Repeat([]byte{7}, 84))
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4+1+BodyLen {
		t.Fatalf("len=%d", buf.Len())
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.CircID != c.CircID || got.Command != CmdCreate2 {
		t.Fatalf("got %+v", got)
	}
	ht, hd, err := ParseCreate2(got.Body)
	if err != nil || ht != 2 || len(hd) != 84 || hd[0] != 7 {
		t.Fatalf("ht=%d hd=%v err=%v", ht, hd, err)
	}
}

func TestVersionsRoundTrip(t *testing.T) {
	c := Versions(2, 4, 5)
	var buf bytes.Buffer
	if err := c.Write(&buf, 2); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 2)
	if err != nil {
		t.Fatal(err)
	}
	vs, err := ParseVersions(got.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(vs) != 2 || vs[0] != 4 || vs[1] != 5 {
		t.Fatalf("%v", vs)
	}
	v, err := NegotiateVersion([]uint16{3, 4, 5}, []uint16{4, 5})
	if err != nil || v != 5 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}

func TestNegotiateNoCommon(t *testing.T) {
	if _, err := NegotiateVersion([]uint16{3}, []uint16{4, 5}); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseVersionsOddLength(t *testing.T) {
	if _, err := ParseVersions([]byte{0, 4, 0}); err == nil {
		t.Fatal("expected error")
	}
}

func TestVarLenCerts(t *testing.T) {
	c := &Cell{Command: CmdCerts, Body: []byte{1, 2, 3, 4}}
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdCerts || !bytes.Equal(got.Body, c.Body) {
		t.Fatalf("%+v", got)
	}
}

func TestPaddingRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := Padding().Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4+1+BodyLen {
		t.Fatalf("len=%d", buf.Len())
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.CircID != 0 || got.Command != CmdPadding || len(got.Body) != BodyLen {
		t.Fatalf("%+v", got)
	}
}

func TestVpaddingRoundTrip(t *testing.T) {
	body := bytes.Repeat([]byte{0xab}, 17)
	var buf bytes.Buffer
	if err := Vpadding(body).Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 4+1+2+17 {
		t.Fatalf("len=%d", buf.Len())
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdVpadding || !bytes.Equal(got.Body, body) {
		t.Fatalf("%+v", got)
	}
}

func TestCreateFastCells(t *testing.T) {
	x := bytes.Repeat([]byte{1}, 20)
	y := bytes.Repeat([]byte{2}, 20)
	kh := bytes.Repeat([]byte{3}, 20)
	var buf bytes.Buffer
	if err := CreateFast(0x80000003, x).Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	px, err := ParseCreateFast(got.Body)
	if err != nil || !bytes.Equal(px, x) {
		t.Fatalf("%v %v", px, err)
	}
	buf.Reset()
	if err := CreatedFast(0x80000003, y, kh).Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err = Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	gy, gkh, err := ParseCreatedFast(got.Body)
	if err != nil || !bytes.Equal(gy, y) || !bytes.Equal(gkh, kh) {
		t.Fatalf("%v %v %v", gy, gkh, err)
	}
}

func TestDestroy(t *testing.T) {
	c := Destroy(0x80000002, DestroyConnectFailed)
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdDestroy || got.Body[0] != DestroyConnectFailed {
		t.Fatalf("%+v", got)
	}
}

func TestDestroyReasons(t *testing.T) {
	if DestroyNone != 0 || DestroyProtocol != 1 || DestroyInternal != 2 || DestroyRequested != 3 {
		t.Fatalf("none/protocol/internal/requested")
	}
	if DestroyConnectFailed != 6 || DestroyORIdentity != 7 || DestroyChannelClosed != 8 || DestroyDestroyed != 11 {
		t.Fatalf("connect/identity/channel/destroyed")
	}
	if DestroyReason(nil) != DestroyNone || DestroyReason([]byte{DestroyRequested}) != DestroyRequested {
		t.Fatal("DestroyReason")
	}
}

func TestCreated2(t *testing.T) {
	raw := Created2(7, bytes.Repeat([]byte{9}, 64))
	h, err := ParseCreated2(raw.Body)
	if err != nil || len(h) != 64 || h[0] != 9 {
		t.Fatalf("%v %v", h, err)
	}
	if _, err := ParseCreated2([]byte{0}); err == nil {
		t.Fatal("short CREATED2")
	}
	if _, _, err := ParseCreate2([]byte{0, 2}); err == nil {
		t.Fatal("short CREATE2")
	}
}

func TestRelayEncode(t *testing.T) {
	body := EncodeRelay(Relay{Command: RelayBegin, StreamID: 7, Data: []byte("example.com:80")})
	if len(body) != BodyLen {
		t.Fatalf("len %d", len(body))
	}
	if !RecognizedZero(body) {
		t.Fatal("recognized")
	}
	msg, err := DecodeRelay(body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != RelayBegin || msg.StreamID != 7 {
		t.Fatalf("%+v", msg)
	}
	h, p, flags, err := ParseBegin(BeginPayload("example.com", 80))
	if err != nil || h != "example.com" || p != 80 || flags != 0 {
		t.Fatalf("%s %d flags=%d %v", h, p, flags, err)
	}
	h, p, flags, err = ParseBegin(BeginPayload("127.0.0.1", 8080))
	if err != nil || h != "127.0.0.1" || p != 8080 || flags != 0 {
		t.Fatalf("%s %d flags=%d %v", h, p, flags, err)
	}
	if _, _, _, err := ParseBegin([]byte("noport")); err == nil {
		t.Fatal("expected bad begin")
	}
}

func TestBeginFlags(t *testing.T) {
	want := BeginIPv6OK | BeginIPv4NotOK | BeginIPv6Preferred
	raw := BeginPayloadFlags("example.com", 443, want)
	h, p, flags, err := ParseBegin(raw)
	if err != nil || h != "example.com" || p != 443 || flags != want {
		t.Fatalf("%s %d flags=%d err=%v", h, p, flags, err)
	}
	if len(BeginPayload("x", 1)) != len("x:1")+1 {
		t.Fatal("zero flags should omit FLAGS")
	}
}

func TestSelectBeginAddr(t *testing.T) {
	v4 := net.ParseIP("1.2.3.4")
	v6 := net.ParseIP("2001:db8::1")
	both := []net.IP{v4, v6}
	if got := SelectBeginAddr(both, 0); !got.Equal(v4) {
		t.Fatalf("default %v", got)
	}
	if got := SelectBeginAddr(both, BeginIPv6OK|BeginIPv6Preferred); !got.Equal(v6) {
		t.Fatalf("prefer v6 %v", got)
	}
	if got := SelectBeginAddr([]net.IP{v4}, BeginIPv4NotOK); got != nil {
		t.Fatalf("v4 not ok %v", got)
	}
	if got := SelectBeginAddr([]net.IP{v6}, BeginIPv6OK); !got.Equal(v6) {
		t.Fatalf("v6 only %v", got)
	}
}

func TestSendmeV1RoundTrip(t *testing.T) {
	d := bytes.Repeat([]byte{0x11}, 20)
	ver, got, err := ParseSendme(EncodeSendmeV1(d))
	if err != nil || ver != SendmeV1 || !bytes.Equal(got, d) {
		t.Fatalf("ver=%d got=%x err=%v", ver, got, err)
	}
	ver, got, err = ParseSendme(nil)
	if err != nil || ver != 0 || got != nil {
		t.Fatalf("v0 ver=%d got=%x err=%v", ver, got, err)
	}
	if _, _, err := ParseSendme([]byte{1, 0, 5, 1, 2, 3}); err == nil {
		t.Fatal("short digest")
	}
}

func TestPaddingNegotiateRoundTrip(t *testing.T) {
	raw := EncodePaddingNegotiate(CircPadCommandStart, CircPadMachineCircSetup, 7)
	n, err := ParsePaddingNegotiate(raw)
	if err != nil || n.Version != 0 || n.Command != CircPadCommandStart || n.MachineType != CircPadMachineCircSetup || n.MachineCtr != 7 {
		t.Fatalf("%+v %v", n, err)
	}
	got, err := ParsePaddingNegotiated(EncodePaddingNegotiated(CircPadCommandStart, CircPadResponseERR, CircPadMachineCircSetup, 7))
	if err != nil || got.Response != CircPadResponseERR || got.Command != CircPadCommandStart || got.MachineCtr != 7 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParsePaddingNegotiate([]byte{0, 1, 1}); err == nil {
		t.Fatal("short negotiate")
	}
}

func TestResolveRoundTrip(t *testing.T) {
	if ParseResolve(EncodeResolve("example.com")) != "example.com" {
		t.Fatal("hostname")
	}
	ans := []Resolved{
		{Type: ResolvedIPv4, Value: []byte{127, 0, 0, 1}, TTL: 60},
		{Type: ResolvedIPv6, Value: make([]byte, 16), TTL: 30},
	}
	got, err := ParseResolved(EncodeResolved(ans))
	if err != nil || len(got) != 2 || got[0].Type != ResolvedIPv4 || got[0].TTL != 60 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Value[0] != 127 {
		t.Fatal(got[0].Value)
	}
}

func TestZeroDigest(t *testing.T) {
	body := EncodeRelay(Relay{Command: RelayData, StreamID: 1, Data: []byte("x")})
	SetDigest(body, []byte{1, 2, 3, 4})
	z := ZeroDigest(body)
	if z[5] != 0 || z[6] != 0 || z[7] != 0 || z[8] != 0 {
		t.Fatal(z[5:9])
	}
	if body[5] != 1 {
		t.Fatal("original mutated")
	}
}

func TestExtend2(t *testing.T) {
	var ip [4]byte
	copy(ip[:], []byte{10, 0, 0, 2})
	var id [20]byte
	id[0] = 9
	ed := make([]byte, 32)
	ed[1] = 3
	b := EncodeExtend2(ip, 9001, id, ed, HTypenTor, bytes.Repeat([]byte{1}, 84))
	e, err := ParseExtend2(b)
	if err != nil {
		t.Fatal(err)
	}
	gotIP, port, ok := e.IPv4Port()
	if !ok || gotIP != ip || port != 9001 {
		t.Fatalf("ip %v port %d", gotIP, port)
	}
	lid, ok := e.LegacyID()
	if !ok || lid != id {
		t.Fatalf("id %v", lid)
	}
	if e.HType != HTypenTor || len(e.HData) != 84 {
		t.Fatalf("handshake %+v", e)
	}
	if _, err := ParseExtend2([]byte{3}); err == nil {
		t.Fatal("short extend2")
	}
}

func TestIsVarLen(t *testing.T) {
	if !IsVarLen(CmdVersions) || !IsVarLen(CmdCerts) || IsVarLen(CmdRelay) || IsVarLen(CmdCreate2) {
		t.Fatal("varlen classification")
	}
	if CircIDLen(3) != 2 || CircIDLen(4) != 4 || CircIDLen(5) != 4 {
		t.Fatal("circid len")
	}
}
