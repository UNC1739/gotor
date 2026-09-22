package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
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
		{{CertTypeIdentityVSigning}, {1, 2, 3}},
		{{CertTypeSigningVTLSCert}, {4, 5}},
	})
	m, err := ParseCERTS(body)
	if err != nil {
		t.Fatal(err)
	}
	if string(m[CertTypeIdentityVSigning]) != string([]byte{1, 2, 3}) {
		t.Fatalf("%v", m)
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

func TestAuthChallengeLength(t *testing.T) {
	b := EncodeAuthChallenge()
	if len(b) != 36 {
		t.Fatalf("len %d", len(b))
	}
}

func TestRSAIdentityCertDigest(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	der, err := EncodeRSAIdentityCert(key)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := ParseRSAIdentityCert(der)
	if err != nil {
		t.Fatal(err)
	}
	got := RSAIdentityDigest(pub)
	want := sha1.Sum(x509.MarshalPKCS1PublicKey(&key.PublicKey))
	if got != want {
		t.Fatalf("%x vs %x", got, want)
	}
}

func TestRSAEdCrossCert(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := EncodeRSAEdCrossCert(edPub, key, 24)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyRSAEdCrossCert(raw, &key.PublicKey, edPub); err != nil {
		t.Fatal(err)
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if err := VerifyRSAEdCrossCert(raw, &key.PublicKey, other); err == nil {
		t.Fatal("expected subject mismatch")
	}
	raw[len(raw)-1] ^= 0xff
	if err := VerifyRSAEdCrossCert(raw, &key.PublicKey, edPub); err == nil {
		t.Fatal("expected signature failure")
	}
}

func TestVerifyCERTSRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	x509der, err := EncodeRSAIdentityCert(key)
	if err != nil {
		t.Fatal(err)
	}
	cc, err := EncodeRSAEdCrossCert(edPub, key, 24)
	if err != nil {
		t.Fatal(err)
	}
	m := map[byte][]byte{
		CertTypeRSAIDX509:      x509der,
		CertTypeRSAIDVIdentity: cc,
	}
	pub, err := VerifyCERTSRSA(m, edPub)
	if err != nil {
		t.Fatal(err)
	}
	if RSAIdentityDigest(pub) != RSAIdentityDigest(&key.PublicKey) {
		t.Fatal("rsa digest")
	}
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := VerifyCERTSRSA(m, other); err == nil {
		t.Fatal("expected type 7 mismatch")
	}
	if _, err := VerifyCERTSRSA(map[byte][]byte{CertTypeRSAIDX509: x509der}, edPub); err == nil {
		t.Fatal("expected incomplete 2/7")
	}
	pub, err = VerifyCERTSRSA(map[byte][]byte{}, edPub)
	if err != nil || pub != nil {
		t.Fatal("absent 2/7 should be skipped")
	}
}
