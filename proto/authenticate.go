package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
)

const (
	AuthTypeEd25519 = 0x0003
	authTypeStr     = "AUTH0003"
	exporterLabel   = "EXPORTER FOR TOR TLS CLIENT BINDING AUTH0003"
	authPayloadLen  = 8 + 32*8 + 24 + 64
)

func cellBytes(c *cell.Cell, circIDLen int) []byte {
	var buf bytes.Buffer
	_ = c.Write(&buf, circIDLen)
	return buf.Bytes()
}

func digestLog(vers *cell.Cell, restCircIDLen int, rest ...*cell.Cell) [32]byte {
	h := sha256.New()
	h.Write(cellBytes(vers, 2))
	for _, c := range rest {
		h.Write(cellBytes(c, restCircIDLen))
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

func parseAuthChallenge(body []byte) (methods []uint16, err error) {
	if len(body) < 34 {
		return nil, fmt.Errorf("short AUTH_CHALLENGE")
	}
	n := int(binary.BigEndian.Uint16(body[32:34]))
	if len(body) < 34+n*2 {
		return nil, fmt.Errorf("short AUTH_CHALLENGE methods")
	}
	for i := range n {
		methods = append(methods, binary.BigEndian.Uint16(body[34+2*i:]))
	}
	return methods, nil
}

func hasAuthMethod(methods []uint16, m uint16) bool {
	for _, x := range methods {
		if x == m {
			return true
		}
	}
	return false
}

func encodeAuthenticate(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint16(out[0:2], AuthTypeEd25519)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(payload)))
	copy(out[4:], payload)
	return out
}

func parseAuthenticate(body []byte) (authType uint16, payload []byte, err error) {
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("short AUTHENTICATE")
	}
	authType = binary.BigEndian.Uint16(body[0:2])
	n := int(binary.BigEndian.Uint16(body[2:4]))
	if len(body) < 4+n {
		return 0, nil, fmt.Errorf("short AUTHENTICATE payload")
	}
	return authType, body[4 : 4+n], nil
}

func buildAuthenticate(ch *Channel, initID, respID ed25519.PublicKey, slog, clog [32]byte, linkPriv ed25519.PrivateKey) ([]byte, error) {
	st := ch.Conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS peer certificate")
	}
	cid := sha256.Sum256(initID)
	sid := sha256.Sum256(respID)
	scert := sha256.Sum256(st.PeerCertificates[0].Raw)
	tlssec, err := st.ExportKeyingMaterial(exporterLabel, cid[:], 32)
	if err != nil {
		return nil, err
	}
	payload := make([]byte, authPayloadLen)
	copy(payload[0:8], authTypeStr)
	copy(payload[8:40], cid[:])
	copy(payload[40:72], sid[:])
	copy(payload[72:104], initID)
	copy(payload[104:136], respID)
	copy(payload[136:168], slog[:])
	copy(payload[168:200], clog[:])
	copy(payload[200:232], scert[:])
	copy(payload[232:264], tlssec)
	if _, err := rand.Read(payload[264:288]); err != nil {
		return nil, err
	}
	copy(payload[288:], ed25519.Sign(linkPriv, payload[:288]))
	return encodeAuthenticate(payload), nil
}

func verifyAuthenticate(ch *Channel, keys ResponderKeys, initID, linkPub ed25519.PublicKey, slog, clog [32]byte, body []byte) error {
	typ, payload, err := parseAuthenticate(body)
	if err != nil {
		return err
	}
	if typ != AuthTypeEd25519 {
		return fmt.Errorf("unsupported AUTH type %d", typ)
	}
	if len(payload) < authPayloadLen {
		return fmt.Errorf("short AUTH0003")
	}
	if string(payload[0:8]) != authTypeStr {
		return fmt.Errorf("bad AUTH TYPE")
	}
	cid := sha256.Sum256(initID)
	sid := sha256.Sum256(keys.IDPub)
	if !hmac.Equal(payload[8:40], cid[:]) || !hmac.Equal(payload[40:72], sid[:]) {
		return fmt.Errorf("CID/SID mismatch")
	}
	if !hmac.Equal(payload[72:104], initID) || !hmac.Equal(payload[104:136], keys.IDPub) {
		return fmt.Errorf("CID_ED/SID_ED mismatch")
	}
	if !hmac.Equal(payload[136:168], slog[:]) || !hmac.Equal(payload[168:200], clog[:]) {
		return fmt.Errorf("log digest mismatch")
	}
	scert := sha256.Sum256(keys.TLSCertDER)
	if !hmac.Equal(payload[200:232], scert[:]) {
		return fmt.Errorf("SCERT mismatch")
	}
	st := ch.Conn.ConnectionState()
	tlssec, err := st.ExportKeyingMaterial(exporterLabel, cid[:], 32)
	if err != nil {
		return err
	}
	if !hmac.Equal(payload[232:264], tlssec) {
		return fmt.Errorf("TLSSECRETS mismatch")
	}
	if !ed25519.Verify(linkPub, payload[:288], payload[288:352]) {
		return fmt.Errorf("AUTHENTICATE signature")
	}
	return nil
}

func verifyInitiatorCERTS(body []byte) (idPub, linkPub ed25519.PublicKey, err error) {
	m, err := certs.ParseCERTS(body)
	if err != nil {
		return nil, nil, err
	}
	raw4, ok := m[certs.CertTypeIdentityVSigning]
	if !ok {
		return nil, nil, fmt.Errorf("initiator CERTS missing identity->signing")
	}
	raw6, ok := m[certs.CertTypeSigningVLinkAuth]
	if !ok {
		return nil, nil, fmt.Errorf("initiator CERTS missing signing->link_auth")
	}
	c4, err := certs.ParseEd25519Cert(raw4)
	if err != nil {
		return nil, nil, err
	}
	if err := c4.Verify(c4.SigningKey); err != nil {
		return nil, nil, fmt.Errorf("initiator identity cert: %w", err)
	}
	c6, err := certs.ParseEd25519Cert(raw6)
	if err != nil {
		return nil, nil, err
	}
	if err := c6.Verify(c4.CertifiedKey[:]); err != nil {
		return nil, nil, fmt.Errorf("link auth cert: %w", err)
	}
	return c4.SigningKey, c6.CertifiedKey[:], nil
}
