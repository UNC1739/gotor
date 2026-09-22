package certs

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

const rsaEdPrefix = "Tor TLS RSA/Ed25519 cross-certificate"

func RSAIdentityDigest(pub *rsa.PublicKey) [20]byte {
	return sha1.Sum(x509.MarshalPKCS1PublicKey(pub))
}

func EncodeRSAIdentityCert(key *rsa.PrivateKey) ([]byte, error) {
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "gotor rsa identity"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	return x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
}

func ParseRSAIdentityCert(der []byte) (*rsa.PublicKey, error) {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	pub, ok := c.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("RSA identity cert is not RSA")
	}
	if err := c.CheckSignatureFrom(c); err != nil {
		return nil, fmt.Errorf("RSA identity cert: %w", err)
	}
	return pub, nil
}

func EncodeRSAEdCrossCert(ed ed25519.PublicKey, key *rsa.PrivateKey, hoursValid uint32) ([]byte, error) {
	exp := uint32(time.Now().Unix()/3600) + hoursValid
	signed := make([]byte, 36)
	copy(signed[:32], ed)
	binary.BigEndian.PutUint32(signed[32:36], exp)
	sum := sha256.Sum256(append([]byte(rsaEdPrefix), signed...))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, sum[:])
	if err != nil {
		return nil, err
	}
	if len(sig) > 255 {
		return nil, fmt.Errorf("RSA signature too long for type 7")
	}
	out := make([]byte, 37+len(sig))
	copy(out, signed)
	out[36] = byte(len(sig))
	copy(out[37:], sig)
	return out, nil
}

func VerifyRSAEdCrossCert(raw []byte, rsaPub *rsa.PublicKey, expectEd ed25519.PublicKey) error {
	if len(raw) < 37 {
		return fmt.Errorf("short RSA→Ed cross-cert")
	}
	siglen := int(raw[36])
	if len(raw) < 37+siglen {
		return fmt.Errorf("short RSA→Ed signature")
	}
	if expectEd != nil && !bytes.Equal(raw[:32], expectEd) {
		return fmt.Errorf("RSA→Ed subject mismatch")
	}
	sum := sha256.Sum256(append([]byte(rsaEdPrefix), raw[:36]...))
	if err := rsa.VerifyPKCS1v15(rsaPub, 0, sum[:], raw[37:37+siglen]); err != nil {
		return fmt.Errorf("RSA→Ed signature: %w", err)
	}
	return nil
}

func VerifyCERTSRSA(m map[byte][]byte, edID ed25519.PublicKey) (*rsa.PublicKey, error) {
	raw2, ok2 := m[CertTypeRSAIDX509]
	raw7, ok7 := m[CertTypeRSAIDVIdentity]
	if !ok2 && !ok7 {
		return nil, nil
	}
	if !ok2 || !ok7 {
		return nil, fmt.Errorf("CERTS type 2/7 incomplete")
	}
	pub, err := ParseRSAIdentityCert(raw2)
	if err != nil {
		return nil, err
	}
	if err := VerifyRSAEdCrossCert(raw7, pub, edID); err != nil {
		return nil, err
	}
	return pub, nil
}
