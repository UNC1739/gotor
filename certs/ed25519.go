package certs

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"fmt"
	"math/big"
	"time"
)

const (
	CertTypeRSAIDX509        = 2
	CertTypeIdentityVSigning = 4
	CertTypeSigningVTLSCert  = 5
	CertTypeSigningVLinkAuth = 6
	CertTypeRSAIDVIdentity   = 7
	KeyTypeEd25519           = 1
	KeyTypeSHA256X509        = 3
	ExtSignedWithEd25519     = 4
)

func EncodeEd25519Cert(certType, keyType byte, certified [32]byte, signer ed25519.PrivateKey, includeSigningPub ed25519.PublicKey, hoursValid uint32) []byte {
	exp := uint32(time.Now().Unix()/3600) + hoursValid
	nExt := byte(0)
	extLen := 0
	if includeSigningPub != nil {
		nExt = 1
		extLen = 2 + 1 + 1 + 32
	}
	body := make([]byte, 1+1+4+1+32+1+extLen)
	off := 0
	body[off] = 1
	off++
	body[off] = certType
	off++
	binary.BigEndian.PutUint32(body[off:], exp)
	off += 4
	body[off] = keyType
	off++
	copy(body[off:], certified[:])
	off += 32
	body[off] = nExt
	off++
	if includeSigningPub != nil {
		binary.BigEndian.PutUint16(body[off:], 32)
		off += 2
		body[off] = ExtSignedWithEd25519
		off++
		body[off] = 0
		off++
		copy(body[off:], includeSigningPub)
		off += 32
	}
	sig := ed25519.Sign(signer, body)
	return append(body, sig...)
}

type EdCert struct {
	Version      byte
	CertType     byte
	Expiration   uint32
	KeyType      byte
	CertifiedKey [32]byte
	SigningKey   ed25519.PublicKey
	Raw          []byte
}

func ParseEd25519Cert(b []byte) (*EdCert, error) {
	if len(b) < 1+1+4+1+32+1+64 {
		return nil, fmt.Errorf("short ed25519 cert")
	}
	c := &EdCert{Raw: b}
	off := 0
	c.Version = b[off]
	off++
	c.CertType = b[off]
	off++
	c.Expiration = binary.BigEndian.Uint32(b[off:])
	off += 4
	c.KeyType = b[off]
	off++
	copy(c.CertifiedKey[:], b[off:off+32])
	off += 32
	nExt := int(b[off])
	off++
	for i := 0; i < nExt; i++ {
		if off+4 > len(b)-64 {
			return nil, fmt.Errorf("short extension")
		}
		el := int(binary.BigEndian.Uint16(b[off:]))
		off += 2
		et := b[off]
		off++
		_ = b[off]
		off++
		if off+el > len(b)-64 {
			return nil, fmt.Errorf("short extension body")
		}
		if et == ExtSignedWithEd25519 && el == 32 {
			c.SigningKey = append([]byte(nil), b[off:off+32]...)
		}
		off += el
	}
	if off+64 != len(b) && off+64 > len(b) {
		return nil, fmt.Errorf("truncated signature")
	}
	return c, nil
}

func (c *EdCert) Verify(pub ed25519.PublicKey) error {
	if len(c.Raw) < 64 {
		return fmt.Errorf("no signature")
	}
	msg := c.Raw[:len(c.Raw)-64]
	sig := c.Raw[len(c.Raw)-64:]
	key := pub
	if key == nil {
		key = c.SigningKey
	}
	if len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("no verifying key")
	}
	if !ed25519.Verify(key, msg, sig) {
		return fmt.Errorf("ed25519 cert signature mismatch")
	}
	hours := uint32(time.Now().Unix() / 3600)
	if hours > c.Expiration {
		return fmt.Errorf("ed25519 cert expired")
	}
	return nil
}

func EncodeCERTS(certs [][2][]byte) []byte {
	n := 1
	for _, c := range certs {
		n += 1 + 2 + len(c[1])
	}
	buf := make([]byte, n)
	buf[0] = byte(len(certs))
	off := 1
	for _, c := range certs {
		buf[off] = c[0][0]
		off++
		binary.BigEndian.PutUint16(buf[off:], uint16(len(c[1])))
		off += 2
		copy(buf[off:], c[1])
		off += len(c[1])
	}
	return buf[:off]
}

func ParseCERTS(body []byte) (map[byte][]byte, error) {
	if len(body) < 1 {
		return nil, fmt.Errorf("short CERTS")
	}
	n := int(body[0])
	off := 1
	out := map[byte][]byte{}
	for i := 0; i < n; i++ {
		if off+3 > len(body) {
			return nil, fmt.Errorf("short CERTS entry")
		}
		t := body[off]
		off++
		l := int(binary.BigEndian.Uint16(body[off:]))
		off += 2
		if off+l > len(body) {
			return nil, fmt.Errorf("short CERTS cert")
		}
		out[t] = append([]byte(nil), body[off:off+l]...)
		off += l
	}
	return out, nil
}

func EncodeAuthChallenge() []byte {
	buf := make([]byte, 32+2+2)
	_, _ = rand.Read(buf[:32])
	binary.BigEndian.PutUint16(buf[32:34], 1)
	binary.BigEndian.PutUint16(buf[34:36], 3)
	return buf
}

func EncodeNetinfo(other NetIP, mine []NetIP) []byte {
	n := 4 + 1 + 1 + len(other.ip) + 1
	for _, a := range mine {
		n += 1 + 1 + len(a.ip)
	}
	buf := make([]byte, n)
	off := 4
	off += putAddr(buf[off:], other)
	buf[off] = byte(len(mine))
	off++
	for _, a := range mine {
		off += putAddr(buf[off:], a)
	}
	return buf[:off]
}

type NetIP struct {
	atype byte
	ip    []byte
}

func IPv4(ip [4]byte) NetIP { return NetIP{atype: 4, ip: ip[:]} }

func putAddr(buf []byte, a NetIP) int {
	buf[0] = a.atype
	buf[1] = byte(len(a.ip))
	copy(buf[2:], a.ip)
	return 2 + len(a.ip)
}

func SelfSignedTLS(hosts []string, ips [][]byte) (*tls.Certificate, []byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return nil, nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "gotor-relay"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     hosts,
	}
	for _, ip := range ips {
		if len(ip) == 4 || len(ip) == 16 {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	tc := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv, Leaf: leaf}
	return tc, der, nil
}

func TLSCertDigest(der []byte) [32]byte {
	return sha256.Sum256(der)
}
