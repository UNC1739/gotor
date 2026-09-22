package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
	"golang.org/x/crypto/sha3"
)

const (
	hsSaltLen   = 16
	hsKeyLen    = 32
	hsIVLen     = 16
	hsMACLen    = 32
	hsLayerPad  = 10000
	hsFakeAuthN = 16
	hsLifetime  = 180
	hsDescSig   = "Tor onion service descriptor sig v3"
	hsSuperStr  = "hsdir-superencrypted-data"
	hsEncStr    = "hsdir-encrypted-data"
)

var ErrHSDescMAC = errors.New("hsdesc: mac mismatch")

type HSIntro struct {
	Address  net.IP
	ORPort   uint16
	OnionKey [32]byte
	EncKey   [32]byte
	AuthKey  []byte
}

func BuildHSDesc(r io.Reader, id *HSIdentity, intro HSIntro, revision uint64) (string, error) {
	return BuildHSDescAt(r, id, intro, revision, HSPeriodNum, HSPeriodLength)
}

func BuildHSDescAt(r io.Reader, id *HSIdentity, intro HSIntro, revision, periodNum, periodLen uint64) (string, error) {
	blind, err := BlindedFromSecret(id.Private, periodNum, periodLen)
	if err != nil {
		return "", err
	}
	descPub, descPriv, err := ed25519.GenerateKey(r)
	if err != nil {
		return "", err
	}
	sub := Subcredential(id.Public, blind.Public)
	inner := innerPlaintext(intro, descPriv)
	innerCT, err := hsEncrypt(r, append([]byte{}, blind.Public...), sub, revision, hsEncStr, inner)
	if err != nil {
		return "", err
	}
	first := firstLayerPlaintext(r, innerCT)
	first = pad10k(first)
	super, err := hsEncrypt(r, append([]byte{}, blind.Public...), sub, revision, hsSuperStr, first)
	if err != nil {
		return "", err
	}
	var certified [32]byte
	copy(certified[:], descPub)
	cert := certs.EncodeEd25519CertSign(certs.CertTypeHSDescSigning, certs.KeyTypeEd25519, certified, blind.Sign, blind.Public, 12)
	var b strings.Builder
	fmt.Fprintf(&b, "hs-descriptor 3\n")
	fmt.Fprintf(&b, "descriptor-lifetime %d\n", hsLifetime)
	fmt.Fprintf(&b, "descriptor-signing-key-cert\n")
	b.WriteString(pemBlock("ED25519 CERT", cert))
	b.WriteByte('\n')
	fmt.Fprintf(&b, "revision-counter %d\n", revision)
	fmt.Fprintf(&b, "superencrypted\n")
	b.WriteString(pemBlock("MESSAGE", super))
	b.WriteByte('\n')
	signed := b.String()
	sig := ed25519.Sign(descPriv, append([]byte(hsDescSig), signed...))
	fmt.Fprintf(&b, "signature %s\n", base64.StdEncoding.EncodeToString(sig))
	return b.String(), nil
}

func ParseHSDesc(doc string, idPub ed25519.PublicKey) (*HSIntro, error) {
	all, err := ParseHSDescIntrosAt(doc, idPub, HSPeriodNum, HSPeriodLength)
	if err != nil {
		return nil, err
	}
	return all[0], nil
}

func ParseHSDescAt(doc string, idPub ed25519.PublicKey, periodNum, periodLen uint64) (*HSIntro, error) {
	all, err := ParseHSDescIntrosAt(doc, idPub, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	return all[0], nil
}

func ParseHSDescIntrosAt(doc string, idPub ed25519.PublicKey, periodNum, periodLen uint64) ([]*HSIntro, error) {
	rev, super, err := parseOuter(doc)
	if err != nil {
		return nil, err
	}
	blind, err := BlindPublic(idPub, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	sub := Subcredential(idPub, blind)
	first, err := hsDecrypt(append([]byte{}, blind...), sub, rev, hsSuperStr, super)
	if err != nil {
		return nil, err
	}
	innerCT, err := parseEncryptedField(first)
	if err != nil {
		return nil, err
	}
	inner, err := hsDecrypt(append([]byte{}, blind...), sub, rev, hsEncStr, innerCT)
	if err != nil {
		return nil, err
	}
	return parseInners(inner)
}

func innerPlaintext(intro HSIntro, descPriv ed25519.PrivateKey) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "create2-formats 2\n")
	ls := encodeIntroLink(intro)
	fmt.Fprintf(&b, "introduction-point %s\n", base64.StdEncoding.EncodeToString(ls))
	fmt.Fprintf(&b, "onion-key ntor %s\n", base64.StdEncoding.EncodeToString(intro.OnionKey[:]))
	fmt.Fprintf(&b, "enc-key ntor %s\n", base64.StdEncoding.EncodeToString(intro.EncKey[:]))
	if len(intro.AuthKey) == 32 {
		var certified [32]byte
		copy(certified[:], intro.AuthKey)
		cert := certs.EncodeEd25519Cert(certs.CertTypeHSIntroAuth, certs.KeyTypeEd25519, certified, descPriv, descPriv.Public().(ed25519.PublicKey), 54)
		fmt.Fprintf(&b, "auth-key\n")
		b.WriteString(pemBlock("ED25519 CERT", cert))
	}
	return []byte(b.String())
}

func firstLayerPlaintext(r io.Reader, innerCT []byte) []byte {
	eph := make([]byte, 32)
	_, _ = io.ReadFull(r, eph)
	var b strings.Builder
	fmt.Fprintf(&b, "desc-auth-type x25519\n")
	fmt.Fprintf(&b, "desc-auth-ephemeral-key %s\n", base64.StdEncoding.EncodeToString(eph))
	for i := 0; i < hsFakeAuthN; i++ {
		cid := make([]byte, 8)
		iv := make([]byte, 16)
		ck := make([]byte, 16)
		_, _ = io.ReadFull(r, cid)
		_, _ = io.ReadFull(r, iv)
		_, _ = io.ReadFull(r, ck)
		fmt.Fprintf(&b, "auth-client %s %s %s\n",
			base64.StdEncoding.EncodeToString(cid),
			base64.StdEncoding.EncodeToString(iv),
			base64.StdEncoding.EncodeToString(ck))
	}
	fmt.Fprintf(&b, "encrypted\n")
	b.WriteString(pemBlock("MESSAGE", innerCT))
	return []byte(b.String())
}

func encodeIntroLink(intro HSIntro) []byte {
	ip4 := intro.Address.To4()
	if ip4 == nil {
		ip4 = net.IPv4zero.To4()
	}
	buf := make([]byte, 1+1+1+6)
	buf[0] = 1
	buf[1] = cell.LSIPv4
	buf[2] = 6
	copy(buf[3:], ip4)
	binary.BigEndian.PutUint16(buf[7:], intro.ORPort)
	return buf
}

func parseInner(pt []byte) (*HSIntro, error) {
	all, err := parseInners(pt)
	if err != nil {
		return nil, err
	}
	return all[0], nil
}

func introComplete(in *HSIntro) bool {
	return in != nil && in.ORPort != 0 && in.Address != nil && in.OnionKey != [32]byte{} && in.EncKey != [32]byte{} && len(in.AuthKey) == 32
}

func parseInners(pt []byte) ([]*HSIntro, error) {
	lines := strings.Split(string(bytes.TrimRight(pt, "\x00")), "\n")
	var all []*HSIntro
	intro := &HSIntro{}
	flush := func() {
		if introComplete(intro) {
			all = append(all, intro)
		} else if intro.ORPort != 0 && intro.Address != nil && intro.OnionKey != [32]byte{} && intro.EncKey != [32]byte{} {
			all = append(all, intro)
		}
		intro = &HSIntro{}
	}
	for i := 0; i < len(lines); i++ {
		fields := strings.Fields(lines[i])
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "introduction-point":
			flush()
			if len(fields) < 2 {
				continue
			}
			raw, err := decodeB64(fields[1])
			if err != nil || len(raw) < 9 || raw[0] < 1 {
				continue
			}
			off := 1
			for n := 0; n < int(raw[0]) && off+2 <= len(raw); n++ {
				t := raw[off]
				l := int(raw[off+1])
				off += 2
				if off+l > len(raw) {
					break
				}
				if t == cell.LSIPv4 && l == 6 {
					intro.Address = net.IP(append([]byte(nil), raw[off:off+4]...))
					intro.ORPort = binary.BigEndian.Uint16(raw[off+4 : off+6])
				}
				off += l
			}
		case "onion-key":
			if len(fields) >= 3 && fields[1] == "ntor" {
				if raw, err := decodeB64(fields[2]); err == nil && len(raw) == 32 {
					copy(intro.OnionKey[:], raw)
				}
			}
		case "enc-key":
			if len(fields) >= 3 && fields[1] == "ntor" {
				if raw, err := decodeB64(fields[2]); err == nil && len(raw) == 32 {
					copy(intro.EncKey[:], raw)
				}
			}
		case "auth-key":
			if len(fields) >= 3 && fields[1] == "ed25519" {
				if raw, err := decodeB64(fields[2]); err == nil && len(raw) == 32 {
					intro.AuthKey = raw
				}
				continue
			}
			rest := strings.Join(lines[i+1:], "\n")
			block, rest2 := pem.Decode([]byte(rest))
			if block != nil && block.Type == "ED25519 CERT" {
				if c, err := certs.ParseEd25519Cert(block.Bytes); err == nil {
					k := make([]byte, 32)
					copy(k, c.CertifiedKey[:])
					intro.AuthKey = k
				}
				consumed := len(rest) - len(rest2)
				if consumed > 0 {
					i += strings.Count(rest[:consumed], "\n")
				}
			}
		}
	}
	flush()
	if len(all) == 0 {
		return nil, fmt.Errorf("hsdesc: no intro point")
	}
	return all, nil
}

func decodeB64(s string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return base64.RawStdEncoding.DecodeString(s)
	}
	return raw, nil
}

func parseOuter(doc string) (revision uint64, super []byte, err error) {
	var rev uint64
	for _, line := range strings.Split(doc, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "revision-counter" {
			rev, _ = strconv.ParseUint(fields[1], 10, 64)
		}
	}
	idx := strings.Index(doc, "superencrypted")
	if idx < 0 {
		return 0, nil, fmt.Errorf("hsdesc: missing superencrypted")
	}
	rest := doc[idx:]
	begin := strings.Index(rest, "-----BEGIN MESSAGE-----")
	if begin < 0 {
		return 0, nil, fmt.Errorf("hsdesc: superencrypted")
	}
	block, _ := pem.Decode([]byte(rest[begin:]))
	if block == nil || block.Type != "MESSAGE" {
		return 0, nil, fmt.Errorf("hsdesc: superencrypted pem")
	}
	return rev, block.Bytes, nil
}

func parseEncryptedField(first []byte) ([]byte, error) {
	first = bytes.TrimRight(first, "\x00")
	idx := bytes.Index(first, []byte("-----BEGIN MESSAGE-----"))
	if idx < 0 {
		return nil, fmt.Errorf("hsdesc: inner encrypted")
	}
	block, _ := pem.Decode(first[idx:])
	if block == nil || block.Type != "MESSAGE" {
		return nil, fmt.Errorf("hsdesc: inner pem")
	}
	return block.Bytes, nil
}

func pemBlock(typ string, data []byte) string {
	var buf bytes.Buffer
	_ = pem.Encode(&buf, &pem.Block{Type: typ, Bytes: data})
	return strings.TrimRight(buf.String(), "\n")
}

func pad10k(p []byte) []byte {
	n := len(p)
	if n%hsLayerPad == 0 {
		if n == 0 {
			return make([]byte, hsLayerPad)
		}
		return p
	}
	return append(p, make([]byte, hsLayerPad-n%hsLayerPad)...)
}

func hsEncrypt(r io.Reader, secretData, subcred []byte, revision uint64, strConst string, plaintext []byte) ([]byte, error) {
	rnd := make([]byte, 32)
	if _, err := io.ReadFull(r, rnd); err != nil {
		return nil, err
	}
	sum := sha3.Sum256(rnd)
	salt := sum[:hsSaltLen]
	sk, iv, mk := hsKeys(secretData, subcred, revision, salt, strConst)
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	enc := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(enc, plaintext)
	mac := hsMAC(mk, salt, enc)
	out := make([]byte, 0, hsSaltLen+len(enc)+hsMACLen)
	out = append(out, salt...)
	out = append(out, enc...)
	out = append(out, mac...)
	return out, nil
}

func hsDecrypt(secretData, subcred []byte, revision uint64, strConst string, blob []byte) ([]byte, error) {
	if len(blob) < hsSaltLen+hsMACLen {
		return nil, fmt.Errorf("hsdesc: short blob")
	}
	salt := blob[:hsSaltLen]
	mac := blob[len(blob)-hsMACLen:]
	enc := blob[hsSaltLen : len(blob)-hsMACLen]
	sk, iv, mk := hsKeys(secretData, subcred, revision, salt, strConst)
	if !hmac.Equal(mac, hsMAC(mk, salt, enc)) {
		return nil, ErrHSDescMAC
	}
	block, err := aes.NewCipher(sk)
	if err != nil {
		return nil, err
	}
	pt := make([]byte, len(enc))
	cipher.NewCTR(block, iv).XORKeyStream(pt, enc)
	return pt, nil
}

func hsKeys(secretData, subcred []byte, revision uint64, salt []byte, strConst string) (sk, iv, mk []byte) {
	var rev [8]byte
	binary.BigEndian.PutUint64(rev[:], revision)
	in := append(append(append(append([]byte{}, secretData...), subcred...), rev[:]...), salt...)
	in = append(in, strConst...)
	h := sha3.NewShake256()
	h.Write(in)
	keys := make([]byte, hsKeyLen+hsIVLen+hsMACLen)
	_, _ = h.Read(keys)
	return keys[:hsKeyLen], keys[hsKeyLen : hsKeyLen+hsIVLen], keys[hsKeyLen+hsIVLen:]
}

func hsMAC(mk, salt, enc []byte) []byte {
	d := sha3.New256()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(mk)))
	d.Write(n[:])
	d.Write(mk)
	binary.BigEndian.PutUint64(n[:], uint64(len(salt)))
	d.Write(n[:])
	d.Write(salt)
	d.Write(enc)
	return d.Sum(nil)
}
