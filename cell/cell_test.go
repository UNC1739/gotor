package cell

import (
	"bytes"
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

func TestDestroy(t *testing.T) {
	c := Destroy(0x80000002, 6)
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdDestroy || got.Body[0] != 6 {
		t.Fatalf("%+v", got)
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
	h, p, err := ParseBegin(BeginPayload("example.com", 80))
	if err != nil || h != "example.com" || p != 80 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	h, p, err = ParseBegin(BeginPayload("127.0.0.1", 8080))
	if err != nil || h != "127.0.0.1" || p != 8080 {
		t.Fatalf("%s %d %v", h, p, err)
	}
	if _, _, err := ParseBegin([]byte("noport")); err == nil {
		t.Fatal("expected bad begin")
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
