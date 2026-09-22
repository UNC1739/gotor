package cell

import (
	"bytes"
	"io"
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

func TestNegotiateVersion4Only(t *testing.T) {
	v, err := NegotiateVersion([]uint16{4}, []uint16{4, 5})
	if err != nil || v != 4 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}

func TestNegotiateVersionIgnores6(t *testing.T) {
	v, err := NegotiateVersion([]uint16{4, 5, 6}, []uint16{4, 5})
	if err != nil || v != 5 {
		t.Fatalf("v=%d err=%v", v, err)
	}
}


func TestNegotiateVersionEmpty(t *testing.T) {
	if _, err := NegotiateVersion(nil, []uint16{4, 5}); err == nil {
		t.Fatal("empty ours")
	}
	if _, err := NegotiateVersion([]uint16{4, 5}, nil); err == nil {
		t.Fatal("empty theirs")
	}
}

func TestParseCreate2TrailingExtra(t *testing.T) {
	body := append([]byte{0x00, 0x02, 0x00, 0x02, 0xaa, 0xbb}, bytes.Repeat([]byte{0}, 20)...)
	ht, hd, err := ParseCreate2(body)
	if err != nil || ht != 2 || len(hd) != 2 || hd[0] != 0xaa {
		t.Fatalf("ht=%d hd=%x err=%v", ht, hd, err)
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

func TestParseSendmeV1TrailingAndV2(t *testing.T) {
	d := bytes.Repeat([]byte{0x33}, 20)
	raw := append(EncodeSendmeV1(d), 0xaa, 0xbb)
	ver, got, err := ParseSendme(raw)
	if err != nil || ver != SendmeV1 || !bytes.Equal(got, d) {
		t.Fatalf("trail ver=%d got=%x err=%v", ver, got, err)
	}
	ver, got, err = ParseSendme([]byte{2, 0, 0})
	if err != nil || ver != 2 || got != nil {
		t.Fatalf("v2 ver=%d got=%x err=%v", ver, got, err)
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

func TestParseResolveStopsAtNUL(t *testing.T) {
	if ParseResolve([]byte("example.com\x00junk")) != "example.com" {
		t.Fatal("nul")
	}
	if ParseResolve([]byte("only")) != "only" {
		t.Fatal("no nul")
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
	if IsVarLen(127) || !IsVarLen(128) || !IsVarLen(255) {
		t.Fatal("varlen 128+ boundary")
	}
	if CircIDLen(3) != 2 || CircIDLen(4) != 4 || CircIDLen(5) != 4 {
		t.Fatal("circid len")
	}
}


func TestRelayHeaderCTorVector(t *testing.T) {
	body := make([]byte, BodyLen)
	copy(body, []byte{0x03, 0x00, 0x00, 0x21, 0x22, 'A', 'B', 'C', 'D', 0x01, 0x03})
	msg, err := DecodeRelay(body)
	if err != nil {
		t.Fatal(err)
	}
	if msg.Command != 3 || msg.StreamID != 0x2122 || msg.Digest != [4]byte{'A', 'B', 'C', 'D'} {
		t.Fatalf("%+v", msg)
	}
	if len(msg.Data) != 0x103 {
		t.Fatalf("len %d", len(msg.Data))
	}
	if !RecognizedZero(body) {
		t.Fatal("recognized")
	}
}

func TestParseBeginCTorCases(t *testing.T) {
	tests := []struct {
		in      string
		host    string
		port    uint16
		wantErr bool
	}{
		{"a.b:9\x00", "a.b", 9, false},
		{"here-is-a-nice-long.hostname.com:65535\x00", "here-is-a-nice-long.hostname.com", 65535, false},
		{"18.9.22.169:80\x00", "18.9.22.169", 80, false},
		{"[2620::6b0:b:1a1a:0:26e5:480e]:80\x00", "[2620::6b0:b:1a1a:0:26e5:480e]", 80, false},
		{"::ffff:127.0.0.1:80\x00", "::ffff:127.0.0.1", 80, false},
		{"another.example.com:80\x00\x01\x02", "another.example.com", 80, false},
		{"another.example.com:443\x00\x01\x02\x03\x04", "another.example.com", 443, false},
		{"a-further.example.com:22\x00\xee\xaa\x00\xffHi mom", "a-further.example.com", 22, false},
		{"", "", 0, true},
		{"a.b\x00", "", 0, true},
		{"a.b:\x00", "", 0, true},
		{"a.b:xyz\x00", "", 0, true},
		{"a.b:100000\x00", "", 0, true},
		{"a.b:80", "a.b", 80, false},
	}
	for _, tc := range tests {
		h, p, err := ParseBegin([]byte(tc.in))
		if tc.wantErr {
			if err == nil {
				t.Fatalf("%q: expected error", tc.in)
			}
			continue
		}
		if err != nil || h != tc.host || p != tc.port {
			t.Fatalf("%q: host=%q port=%d err=%v", tc.in, h, p, err)
		}
	}
}

func TestDecodeRelayErrors(t *testing.T) {
	if _, err := DecodeRelay(make([]byte, 10)); err == nil {
		t.Fatal("short body")
	}
	body := make([]byte, BodyLen)
	body[9] = 0x01
	body[10] = 0xf4
	if _, err := DecodeRelay(body); err == nil {
		t.Fatal("length 500 overflows payload")
	}
}

func TestEncodeRelayTruncates(t *testing.T) {
	msg, err := DecodeRelay(EncodeRelay(Relay{Command: RelayData, StreamID: 1, Data: bytes.Repeat([]byte{'x'}, MaxRelayData+40)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(msg.Data) != MaxRelayData {
		t.Fatalf("len %d", len(msg.Data))
	}
}

func TestCreate2LengthMismatch(t *testing.T) {
	if _, _, err := ParseCreate2([]byte{0, 2, 0, 10, 1, 2, 3}); err == nil {
		t.Fatal("CREATE2 claimed 10 bytes")
	}
	if _, err := ParseCreated2([]byte{0, 10, 1, 2}); err == nil {
		t.Fatal("CREATED2 claimed 10 bytes")
	}
	if _, err := ParseCreateFast(make([]byte, 19)); err == nil {
		t.Fatal("short CREATE_FAST")
	}
	if _, _, err := ParseCreatedFast(make([]byte, 39)); err == nil {
		t.Fatal("short CREATED_FAST")
	}
}

func TestWriteCircIDTooLarge(t *testing.T) {
	c := &Cell{CircID: 0x10000, Command: CmdDestroy, Body: []byte{1}}
	var buf bytes.Buffer
	if err := c.Write(&buf, 2); err == nil {
		t.Fatal("expected overflow")
	}
}

func TestReadTruncated(t *testing.T) {
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0}), 4); err == nil {
		t.Fatal("truncated fixed")
	}
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0, 0, CmdVersions}), 4); err == nil {
		t.Fatal("truncated varlen length")
	}
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0, 0, CmdVersions, 0, 10}), 4); err == nil {
		t.Fatal("truncated varlen body")
	}
}

func TestReadTruncatedTwoByteCircID(t *testing.T) {
	if _, err := Read(bytes.NewReader([]byte{0, 0, CmdRelay}), 2); err == nil {
		t.Fatal("truncated 2-byte body")
	}
}


func TestSendmeUnparseable(t *testing.T) {
	if _, _, err := ParseSendme([]byte{1}); err == nil {
		t.Fatal("1-byte SENDME")
	}
	ver, dig, err := ParseSendme([]byte{0, 0, 0})
	if err != nil || ver != 0 || dig != nil {
		t.Fatalf("v0-with-header ver=%d dig=%v err=%v", ver, dig, err)
	}
}

func TestSendmeV1TruncatesDigest(t *testing.T) {
	d := bytes.Repeat([]byte{0x22}, 32)
	ver, got, err := ParseSendme(EncodeSendmeV1(d))
	if err != nil || ver != SendmeV1 || len(got) != 20 || got[0] != 0x22 {
		t.Fatalf("trunc ver=%d got=%x err=%v", ver, got, err)
	}
}



func TestResolvedCTorCases(t *testing.T) {
	got, err := ParseResolved(nil)
	if err != nil || len(got) != 0 {
		t.Fatalf("%v %v", got, err)
	}
	raw := EncodeResolved([]Resolved{
		{Type: ResolvedIPv4, Value: []byte{1, 2, 3, 4}, TTL: 3600},
		{Type: ResolvedHostname, Value: []byte("example.com"), TTL: 60},
		{Type: ResolvedErrTransient, Value: []byte("timeout"), TTL: 0},
		{Type: ResolvedErr, Value: []byte("Error resolving hostname"), TTL: 0},
	})
	got, err = ParseResolved(raw)
	if err != nil || len(got) != 4 {
		t.Fatalf("%+v %v", got, err)
	}
	if got[0].Type != ResolvedIPv4 || got[0].TTL != 3600 || got[0].Value[0] != 1 {
		t.Fatalf("%+v", got[0])
	}
	if got[1].Type != ResolvedHostname || string(got[1].Value) != "example.com" {
		t.Fatalf("%+v", got[1])
	}
	if got[2].Type != ResolvedErrTransient || got[3].Type != ResolvedErr {
		t.Fatalf("%+v", got)
	}
	if _, err := ParseResolved([]byte{ResolvedIPv4, 4, 1, 2}); err == nil {
		t.Fatal("truncated IPv4")
	}
	if _, err := ParseResolved([]byte{ResolvedIPv4}); err == nil {
		t.Fatal("truncated header")
	}
	if ParseResolve([]byte("abc")) != "abc" {
		t.Fatal("resolve without NUL")
	}
}

func TestExtend2WithoutEd25519(t *testing.T) {
	var ip [4]byte
	copy(ip[:], []byte{10, 0, 0, 2})
	var id [20]byte
	id[0] = 9
	b := EncodeExtend2(ip, 9001, id, nil, HTypenTor, bytes.Repeat([]byte{1}, 84))
	e, err := ParseExtend2(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(e.Specs) != 2 {
		t.Fatalf("specs %d", len(e.Specs))
	}
	h, err := ParseExtended2(EncodeExtended2(bytes.Repeat([]byte{9}, 64)))
	if err != nil || len(h) != 64 || h[0] != 9 {
		t.Fatalf("%v %v", h, err)
	}
	if _, err := ParseExtend2([]byte{1, LSIPv4, 6, 1, 2, 3}); err == nil {
		t.Fatal("short spec data")
	}
	if _, err := ParseExtend2(b[:31]); err == nil {
		t.Fatal("short handshake")
	}
	if _, err := ParseExtend2(b[:35]); err == nil {
		t.Fatal("short hdata")
	}

	e = &Extend2{}
	if _, _, ok := e.IPv4Port(); ok {
		t.Fatal("empty specs")
	}
	if _, ok := e.LegacyID(); ok {
		t.Fatal("empty id")
	}
}

func TestEmptyVpadding(t *testing.T) {
	var buf bytes.Buffer
	if err := Vpadding(nil).Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdVpadding || len(got.Body) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestTwoByteCircIDRoundTrip(t *testing.T) {
	c := Destroy(0x1234, 2)
	var buf bytes.Buffer
	if err := c.Write(&buf, 2); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 2+1+BodyLen {
		t.Fatalf("len=%d", buf.Len())
	}
	got, err := Read(&buf, 2)
	if err != nil {
		t.Fatal(err)
	}
	if got.CircID != 0x1234 || got.Command != CmdDestroy || got.Body[0] != 2 {
		t.Fatalf("%+v", got)
	}
}

func TestEncodeRelaySmallPadding(t *testing.T) {
	for _, n := range []int{MaxRelayData, MaxRelayData - 1, MaxRelayData - 3} {
		msg, err := DecodeRelay(EncodeRelay(Relay{Command: RelayData, StreamID: 1, Data: bytes.Repeat([]byte{'y'}, n)}))
		if err != nil || len(msg.Data) != n {
			t.Fatalf("n=%d len=%d err=%v", n, len(msg.Data), err)
		}
	}
}

func TestReadEmptyVersions(t *testing.T) {
	got, err := Read(bytes.NewReader([]byte{0, 0, 0, 0, CmdVersions, 0, 0}), 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdVersions || len(got.Body) != 0 {
		t.Fatalf("%+v", got)
	}
}

func TestCreate2NtorCTorVector(t *testing.T) {
	skin := bytes.Repeat([]byte{0xab}, 84)
	body := append([]byte{0x00, 0x02, 0x00, 0x54}, skin...)
	ht, hd, err := ParseCreate2(body)
	if err != nil || ht != 2 || !bytes.Equal(hd, skin) {
		t.Fatalf("ht=%d hd=%x err=%v", ht, hd, err)
	}
	created := append([]byte{0x00, 0x40}, bytes.Repeat([]byte{0xcd}, 64)...)
	h, err := ParseCreated2(created)
	if err != nil || len(h) != 64 || h[0] != 0xcd {
		t.Fatalf("%x %v", h, err)
	}
}

func TestReadTruncatedVarLen(t *testing.T) {
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0, 0, CmdVersions, 0}), 4); err == nil {
		t.Fatal("truncated length")
	}
	if _, err := Read(bytes.NewReader([]byte{0, 0, 0, 0, CmdVersions, 0, 4, 1}), 4); err == nil {
		t.Fatal("truncated body")
	}
}

func TestSendmeV1ShortDigest(t *testing.T) {
	if _, _, err := ParseSendme([]byte{SendmeV1, 0, 10, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10}); err == nil {
		t.Fatal("v1 digest 10")
	}
	if _, _, err := ParseSendme([]byte{SendmeV1, 0, 20, 1, 2, 3}); err == nil {
		t.Fatal("v1 claimed 20")
	}
}

func TestParseExtend2Truncated(t *testing.T) {
	if _, err := ParseExtend2(nil); err == nil {
		t.Fatal("empty")
	}
	if _, err := ParseExtend2([]byte{1, 0, 6}); err == nil {
		t.Fatal("short spec")
	}
	if _, err := ParseExtend2([]byte{0}); err == nil {
		t.Fatal("no handshake")
	}
	if _, err := ParseExtend2([]byte{0, 0, 2, 0, 10}); err == nil {
		t.Fatal("short hdata")
	}
}

func TestResolvedIPv6CTorVector(t *testing.T) {
	raw := []byte{
		0x06, 0x10,
		0x20, 0x02, 0x90, 0x90, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0xf0, 0xf0, 0xab, 0xcd,
		0x02, 0x00, 0x00, 0x01,
	}
	got, err := ParseResolved(raw)
	if err != nil || len(got) != 1 {
		t.Fatalf("%v %v", got, err)
	}
	if got[0].Type != ResolvedIPv6 || got[0].TTL != 0x02000001 || len(got[0].Value) != 16 {
		t.Fatalf("%+v", got[0])
	}
}

func TestRelayEarlyRoundTrip(t *testing.T) {
	body := EncodeRelay(Relay{Command: RelayExtend2, StreamID: 0, Data: []byte("x")})
	c := &Cell{CircID: 0x80000001, Command: CmdRelayEarly, Body: body}
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != CmdRelayEarly || got.CircID != 0x80000001 {
		t.Fatalf("%+v", got)
	}
	msg, err := DecodeRelay(got.Body)
	if err != nil || msg.Command != RelayExtend2 || string(msg.Data) != "x" {
		t.Fatalf("%+v %v", msg, err)
	}
}

func TestRelayEndReason(t *testing.T) {
	msg, err := DecodeRelay(EncodeRelay(Relay{Command: RelayEnd, StreamID: 7, Data: []byte{EndReasonConnectRefused}}))
	if err != nil || msg.Command != RelayEnd || msg.StreamID != 7 || msg.Data[0] != EndReasonConnectRefused {
		t.Fatalf("%+v %v", msg, err)
	}
}

func TestBeginPayloadRoundTrip(t *testing.T) {
	p := BeginPayload("example.com", 443)
	h, port, err := ParseBegin(p)
	if err != nil || h != "example.com" || port != 443 {
		t.Fatalf("host=%s port=%d err=%v", h, port, err)
	}
}

func TestParseExtended2(t *testing.T) {
	hdata := bytes.Repeat([]byte{0xab}, 64)
	got, err := ParseExtended2(EncodeExtended2(hdata))
	if err != nil || !bytes.Equal(got, hdata) {
		t.Fatalf("%x %v", got, err)
	}
}

func TestPaddingNegotiateRoundTrip(t *testing.T) {
	c := &Cell{Command: CmdPaddingNegotiate, Body: []byte{0, 0, 0}}
	if IsVarLen(CmdPaddingNegotiate) {
		t.Fatal("PADDING_NEGOTIATE is fixed")
	}
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil || got.Command != CmdPaddingNegotiate {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestCircIDLen(t *testing.T) {
	if CircIDLen(1) != 2 || CircIDLen(2) != 2 || CircIDLen(3) != 2 {
		t.Fatal("v1-3")
	}
	if CircIDLen(4) != 4 || CircIDLen(5) != 4 || CircIDLen(6) != 4 {
		t.Fatal("v4+")
	}
}


func TestRelayTruncateAndTruncated(t *testing.T) {
	for _, cmd := range []byte{RelayTruncate, RelayTruncated} {
		msg, err := DecodeRelay(EncodeRelay(Relay{Command: cmd, StreamID: 0, Data: []byte{1}}))
		if err != nil || msg.Command != cmd || msg.Data[0] != 1 {
			t.Fatalf("cmd=%d %+v %v", cmd, msg, err)
		}
	}
}

func TestAuthenticateVarLen(t *testing.T) {
	if !IsVarLen(CmdAuthenticate) || !IsVarLen(CmdAuthChallenge) {
		t.Fatal("AUTH cells are varlen")
	}
	c := &Cell{Command: CmdAuthenticate, Body: []byte{1, 2, 3}}
	var buf bytes.Buffer
	if err := c.Write(&buf, 4); err != nil {
		t.Fatal(err)
	}
	got, err := Read(&buf, 4)
	if err != nil || got.Command != CmdAuthenticate || !bytes.Equal(got.Body, c.Body) {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestParseVersionsEmpty(t *testing.T) {
	vs, err := ParseVersions(nil)
	if err != nil || len(vs) != 0 {
		t.Fatalf("%v %v", vs, err)
	}
	if _, err := NegotiateVersion(nil, []uint16{4, 5}); err == nil {
		t.Fatal("empty ours")
	}
	if _, err := NegotiateVersion([]uint16{4, 5}, nil); err == nil {
		t.Fatal("empty theirs")
	}
}

func TestConnectedCTorPayloads(t *testing.T) {
	for _, data := range [][]byte{
		{},
		{0x20, 0x30, 0x40, 0x50},
		{0x02, 0x03, 0x04, 0x05, 0x00, 0x00, 0x0e, 0x10},
	} {
		msg, err := DecodeRelay(EncodeRelay(Relay{Command: RelayConnected, StreamID: 1, Data: data}))
		if err != nil || msg.Command != RelayConnected || !bytes.Equal(msg.Data, data) {
			t.Fatalf("%q %+v %v", data, msg, err)
		}
	}
}

func TestBeginDirCTor(t *testing.T) {
	for _, data := range [][]byte{nil, []byte("12345")} {
		msg, err := DecodeRelay(EncodeRelay(Relay{Command: RelayBeginDir, StreamID: 5, Data: data}))
		if err != nil || msg.Command != RelayBeginDir || msg.StreamID != 5 {
			t.Fatalf("%q %+v %v", data, msg, err)
		}
		if !bytes.Equal(msg.Data, data) && !(len(data) == 0 && len(msg.Data) == 0) {
			t.Fatalf("data %q got %q", data, msg.Data)
		}
	}
}

func TestCreate2UnknownType(t *testing.T) {
	ht, hd, err := ParseCreate2([]byte{0x00, 0x50, 0x00, 0x00})
	if err != nil || ht != 0x50 || len(hd) != 0 {
		t.Fatalf("ht=%d hd=%v err=%v", ht, hd, err)
	}
}

func TestCreated2MaximalAndOverlong(t *testing.T) {
	max := bytes.Repeat([]byte{0xab}, 496)
	body := append([]byte{0x01, 0xf0}, max...)
	h, err := ParseCreated2(body)
	if err != nil || !bytes.Equal(h, max) {
		t.Fatalf("%d %v", len(h), err)
	}
	if _, err := ParseCreated2([]byte{0x02, 0xff}); err == nil {
		t.Fatal("claimed 767")
	}
}

func TestParseCreated2Empty(t *testing.T) {
	h, err := ParseCreated2([]byte{0, 0})
	if err != nil || len(h) != 0 {
		t.Fatalf("%v %v", h, err)
	}
}


func TestDestroyReasons(t *testing.T) {
	for _, reason := range []byte{0, 1, 2, 6, 11} {
		c := Destroy(0x80000002, reason)
		var buf bytes.Buffer
		if err := c.Write(&buf, 4); err != nil {
			t.Fatal(err)
		}
		got, err := Read(&buf, 4)
		if err != nil || got.Command != CmdDestroy || got.Body[0] != reason {
			t.Fatalf("reason=%d %+v %v", reason, got, err)
		}
	}
}

func TestCreateCreatedTAPCells(t *testing.T) {
	tap := bytes.Repeat([]byte{0x7a}, 186)
	for _, cmd := range []byte{CmdCreate, CmdCreated} {
		c := &Cell{CircID: 0x80000004, Command: cmd, Body: tap}
		var buf bytes.Buffer
		if err := c.Write(&buf, 4); err != nil {
			t.Fatal(err)
		}
		got, err := Read(&buf, 4)
		if err != nil || got.Command != cmd || !bytes.Equal(got.Body[:186], tap) {
			t.Fatalf("cmd=%d %+v %v", cmd, got, err)
		}
	}
}

func TestExtend2CTorNtorVector(t *testing.T) {
	skin := bytes.Repeat([]byte{0x11}, 84)
	p := []byte{0x02, 0x00, 0x06, 0x12, 0xf4, 0x00, 0x01, 0xf0, 0xf1, 0x02, 0x14}
	p = append(p, []byte("anarchoindividualist")...)
	p = append(p, 0x00, 0x02, 0x00, 0x54)
	p = append(p, skin...)
	e, err := ParseExtend2(p)
	if err != nil {
		t.Fatal(err)
	}
	ip, port, ok := e.IPv4Port()
	if !ok || ip != [4]byte{18, 244, 0, 1} || port != 61681 {
		t.Fatalf("ip=%v port=%d ok=%v", ip, port, ok)
	}
	id, ok := e.LegacyID()
	if !ok || string(id[:]) != "anarchoindividualist" {
		t.Fatalf("id=%q", id[:])
	}
	if e.HType != 2 || !bytes.Equal(e.HData, skin) {
		t.Fatalf("ht=%d hd=%d", e.HType, len(e.HData))
	}
}

func TestExtend2IPv6AndUnknownSpec(t *testing.T) {
	p := []byte{0x04,
		0x00, 0x06, 0x12, 0xf4, 0x00, 0x01, 0xf0, 0xf1,
		0x02, 0x14}
	p = append(p, []byte("anthropomorphization")...)
	p = append(p, 0x01, 0x12, 0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0xf0, 0xc5, 0x1e, 0x11, 0x12)
	p = append(p, 0xf0, 0x20)
	p = append(p, []byte("upupdowndownleftrightleftrightba")...)
	p = append(p, 0x01, 0x05, 0x00, 0x63)
	p = append(p, bytes.Repeat([]byte{0x22}, 99)...)
	e, err := ParseExtend2(p)
	if err != nil {
		t.Fatal(err)
	}
	ip, port, ok := e.IPv4Port()
	if !ok || ip[0] != 18 || port != 61681 {
		t.Fatalf("%v %d %v", ip, port, ok)
	}
	if e.HType != 0x105 || len(e.HData) != 99 {
		t.Fatalf("ht=%#x n=%d", e.HType, len(e.HData))
	}
	if len(e.Specs) != 4 {
		t.Fatalf("nspec=%d", len(e.Specs))
	}
}

func TestExtended2CTorVectors(t *testing.T) {
	reply := bytes.Repeat([]byte{0x33}, 42)
	h, err := ParseExtended2(append([]byte{0x00, 0x2a}, reply...))
	if err != nil || !bytes.Equal(h, reply) {
		t.Fatalf("%x %v", h, err)
	}
	max := bytes.Repeat([]byte{0x44}, 496)
	h, err = ParseExtended2(append([]byte{0x01, 0xf0}, max...))
	if err != nil || !bytes.Equal(h, max) {
		t.Fatalf("max %d %v", len(h), err)
	}
	if _, err := ParseExtended2([]byte{0x01, 0xf1}); err == nil {
		t.Fatal("too long")
	}
}

func TestIsDestroy(t *testing.T) {
	d := Destroy(1, 2)
	if d.Command != CmdDestroy {
		t.Fatal("destroy")
	}
	if Create2(1, 2, nil).Command == CmdDestroy {
		t.Fatal("create2")
	}
}

type errWriter struct{}

func (errWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

type failAfter struct{ left int }

func (f *failAfter) Write(p []byte) (int, error) {
	if f.left <= 0 {
		return 0, io.ErrClosedPipe
	}
	n := len(p)
	if n > f.left {
		n = f.left
	}
	f.left -= n
	if f.left == 0 && n < len(p) {
		return n, io.ErrClosedPipe
	}
	return n, nil
}

func TestWriteErrors(t *testing.T) {
	if err := Destroy(1, 1).Write(errWriter{}, 4); err == nil {
		t.Fatal("fixed hdr")
	}
	if err := Vpadding([]byte{1, 2, 3}).Write(&failAfter{left: 5}, 4); err == nil {
		t.Fatal("varlen length")
	}
}












