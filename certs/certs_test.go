package certs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestEd25519CertRoundTrip(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var certified [32]byte
	copy(certified[:], signPub)
	raw := EncodeEd25519Cert(CertTypeIdentityVSigning, KeyTypeEd25519, certified, idPriv, idPub, 24)
	c, err := ParseEd25519Cert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(idPub); err != nil {
		t.Fatal(err)
	}
	if c.CertifiedKey != certified {
		t.Fatal("certified key")
	}
}

func TestEd25519CertBadSignature(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	var certified [32]byte
	raw := EncodeEd25519Cert(CertTypeIdentityVSigning, KeyTypeEd25519, certified, idPriv, idPub, 24)
	raw[len(raw)-1] ^= 0xff
	c, err := ParseEd25519Cert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(idPub); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestCERTSCell(t *testing.T) {
	body := EncodeCERTS([][2][]byte{
		{{1}, {1}},                              // C-Tor link (RSA)
		{{2}, {9, 9, 9}},                        // RSA identity
		{{3}, {3}},                              // RSA→Ed25519 crosscert
		{{CertTypeIdentityVSigning}, {1, 2, 3}},
		{{CertTypeSigningVTLSCert}, {4, 5}},
		{{6}, {6}}, // Ed25519 signing→auth
		{{7}, {7}}, // RSA identity→Ed25519
	})
	m, err := ParseCERTS(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(m[CertTypeIdentityVSigning]) != string([]byte{1, 2, 3}) {
		t.Fatalf("%v", m)
	}
	if string(m[2]) != string([]byte{9, 9, 9}) || string(m[7]) != string([]byte{7}) {
		t.Fatalf("rsa types %v", m)
	}
	if _, err := ParseCERTS([]byte{}); err == nil {
		t.Fatal("short")
	}
}



func TestTLSCertDigest(t *testing.T) {
	tc, der, err := SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if tc.Leaf == nil || len(der) == 0 {
		t.Fatal("tls cert")
	}
	sum := TLSCertDigest(der)
	want := sha256.Sum256(der)
	if sum != want {
		t.Fatal("digest")
	}
}

func TestSelfSignedTLSRNGFailure(t *testing.T) {
	old := certRand
	t.Cleanup(func() { certRand = old })
	certRand = bytes.NewReader(nil)
	if _, _, err := SelfSignedTLS(nil, nil); err == nil {
		t.Fatal("expected key rng error")
	}
	certRand = bytes.NewReader(make([]byte, 32))
	if _, _, err := SelfSignedTLS(nil, nil); err == nil {
		t.Fatal("expected serial rng error")
	}
}

func TestSelfSignedTLSSkipsBadIP(t *testing.T) {
	tc, der, err := SelfSignedTLS([]string{"localhost"}, [][]byte{{1, 2, 3}, {127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	if tc.Leaf == nil || len(der) == 0 || len(tc.Leaf.IPAddresses) != 1 {
		t.Fatalf("ips=%v", tc.Leaf.IPAddresses)
	}
}

func TestSelfSignedTLSIPv6(t *testing.T) {
	ip6 := make([]byte, 16)
	ip6[15] = 1
	tc, _, err := SelfSignedTLS(nil, [][]byte{ip6})
	if err != nil {
		t.Fatal(err)
	}
	if len(tc.Leaf.IPAddresses) != 1 || len(tc.Leaf.IPAddresses[0]) != 16 || tc.Leaf.IPAddresses[0][15] != 1 {
		t.Fatalf("ips=%v", tc.Leaf.IPAddresses)
	}
}



func TestAuthChallengeLength(t *testing.T) {
	b := EncodeAuthChallenge()
	if len(b) != 36 {
		t.Fatalf("len %d", len(b))
	}
	if b[32] != 0 || b[33] != 1 || b[34] != 0 || b[35] != 3 {
		t.Fatalf("methods %x", b[32:36])
	}
}


func TestParseCERTSTruncated(t *testing.T) {
	if _, err := ParseCERTS([]byte{1, 4}); err == nil {
		t.Fatal("short entry")
	}
	if _, err := ParseCERTS([]byte{1, 4, 0, 10}); err == nil {
		t.Fatal("short cert body")
	}
}

func TestEd25519CertShort(t *testing.T) {
	if _, err := ParseEd25519Cert([]byte{1, 4}); err == nil {
		t.Fatal("short cert")
	}
}

func TestEd25519CertExpired(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var certified [32]byte
	raw := EncodeEd25519Cert(CertTypeIdentityVSigning, KeyTypeEd25519, certified, idPriv, idPub, 24)
	c, err := ParseEd25519Cert(raw)
	if err != nil {
		t.Fatal(err)
	}
	c.Expiration = 1
	if err := c.Verify(idPub); err == nil {
		t.Fatal("expected expired")
	}
}

func TestEd25519CertWrongKey(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var certified [32]byte
	raw := EncodeEd25519Cert(CertTypeIdentityVSigning, KeyTypeEd25519, certified, idPriv, idPub, 24)
	c, err := ParseEd25519Cert(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(other); err == nil {
		t.Fatal("expected verify failure")
	}
}

func TestNetinfoEncode(t *testing.T) {
	b := EncodeNetinfo(IPv4([4]byte{8, 8, 8, 8}), []NetIP{IPv4([4]byte{127, 0, 0, 1})})
	if len(b) != 17 {
		t.Fatalf("len %d", len(b))
	}
	if b[4] != 4 || b[5] != 4 || b[6] != 8 || b[9] != 8 {
		t.Fatalf("other %x", b[4:10])
	}
	if b[10] != 1 || b[11] != 4 || b[12] != 4 || b[13] != 127 {
		t.Fatalf("mine %x", b[10:])
	}
}

func TestNetinfoIPv6(t *testing.T) {
	v6 := make([]byte, 16)
	v6[15] = 1
	other := NetIP{atype: 6, ip: v6}
	mine := NetIP{atype: 6, ip: v6}
	b := EncodeNetinfo(other, []NetIP{mine})
	if b[4] != 6 || b[5] != 16 || b[4+2+16] != 1 || b[4+2+16+1] != 6 || b[4+2+16+2] != 16 {
		t.Fatalf("%x", b)
	}
}

func TestNetinfoMixedIPv4IPv6(t *testing.T) {
	v6 := make([]byte, 16)
	v6[15] = 1
	b := EncodeNetinfo(IPv4([4]byte{1, 2, 3, 4}), []NetIP{{atype: 6, ip: v6}})
	if b[4] != 4 || b[5] != 4 || b[6] != 1 || b[10] != 1 || b[11] != 6 || b[12] != 16 {
		t.Fatalf("%x", b)
	}
}

func TestNetinfoUnknownAtype(t *testing.T) {
	b := EncodeNetinfo(NetIP{atype: 0, ip: []byte{1, 2}}, nil)
	if b[4] != 0 || b[5] != 2 || b[6] != 1 || b[7] != 2 || b[8] != 0 {
		t.Fatalf("%x", b)
	}
}




func TestEd25519CertShortExtension(t *testing.T) {
	b := make([]byte, 1+1+4+1+32+1+2+1+1+10+64)
	b[0] = 1
	b[39] = 1
	b[41] = 32
	if _, err := ParseEd25519Cert(b); err == nil {
		t.Fatal("short extension body")
	}
}

func TestEd25519CertNoKey(t *testing.T) {
	c := &EdCert{Raw: make([]byte, 80)}
	if err := c.Verify(nil); err == nil {
		t.Fatal("expected no verifying key")
	}
}

func TestEd25519CertShortExtensionHeader(t *testing.T) {
	b := make([]byte, 1+1+4+1+32+1+64)
	b[39] = 1
	if _, err := ParseEd25519Cert(b); err == nil {
		t.Fatal("short extension")
	}
}

func TestEd25519CertNoSignature(t *testing.T) {
	c := &EdCert{Raw: make([]byte, 10)}
	if err := c.Verify(make(ed25519.PublicKey, ed25519.PublicKeySize)); err == nil {
		t.Fatal("expected no signature")
	}
}

func TestParseCERTSEmpty(t *testing.T) {
	m, err := ParseCERTS([]byte{0})
	if err != nil || len(m) != 0 {
		t.Fatalf("%v %v", m, err)
	}
}

func TestNetinfoNoMyAddrs(t *testing.T) {
	b := EncodeNetinfo(IPv4([4]byte{1, 2, 3, 4}), nil)
	if len(b) != 11 || b[4] != 4 || b[10] != 0 {
		t.Fatalf("%x", b)
	}
}

func TestEd25519CertTruncatedSignature(t *testing.T) {
	b := make([]byte, 104)
	b[39] = 1 // nExt; el=0 so parse walks past header then hits truncated sig
	if _, err := ParseEd25519Cert(b); err == nil {
		t.Fatal("truncated signature")
	}
}





