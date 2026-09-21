package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"net"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
)

var SupportedLink = []uint16{4, 5}

type ResponderKeys struct {
	IDPub     ed25519.PublicKey
	IDPriv    ed25519.PrivateKey
	SignPub   ed25519.PublicKey
	SignPriv  ed25519.PrivateKey
	TLSCertDER []byte
	Advertise  [4]byte
}

func HandshakeInitiator(ch *Channel, expectID ed25519.PublicKey) (ed25519.PublicKey, error) {
	if err := ch.WriteVersions(SupportedLink...); err != nil {
		return nil, err
	}
	vc, err := ch.ReadVersions()
	if err != nil {
		return nil, err
	}
	if vc.Command != cell.CmdVersions {
		return nil, fmt.Errorf("expected VERSIONS, got %d", vc.Command)
	}
	theirs, err := cell.ParseVersions(vc.Body)
	if err != nil {
		return nil, err
	}
	v, err := cell.NegotiateVersion(SupportedLink, theirs)
	if err != nil {
		return nil, err
	}
	ch.SetLinkVersion(int(v))

	var certsCell, authCell, netinfoCell *cell.Cell
	for certsCell == nil || authCell == nil || netinfoCell == nil {
		c, err := ch.ReadCell()
		if err != nil {
			return nil, err
		}
		switch c.Command {
		case cell.CmdCerts:
			certsCell = c
		case cell.CmdAuthChallenge:
			authCell = c
		case cell.CmdNetinfo:
			netinfoCell = c
		case cell.CmdVpadding, cell.CmdPadding:
		default:
			return nil, fmt.Errorf("unexpected handshake cell %d", c.Command)
		}
	}
	id, err := verifyResponderCERTS(ch, certsCell.Body, expectID)
	if err != nil {
		return nil, err
	}
	other := [4]byte{}
	if ip4 := ipv4Of(ch.Conn.RemoteAddr()); ip4 != nil {
		copy(other[:], ip4)
	}
	ni := &cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4(other), nil)}
	if err := ch.WriteCell(ni); err != nil {
		return nil, err
	}
	return id, nil
}

func HandshakeResponder(ch *Channel, keys ResponderKeys) error {
	vc, err := ch.ReadVersions()
	if err != nil {
		return err
	}
	if vc.Command != cell.CmdVersions {
		return fmt.Errorf("expected VERSIONS, got %d", vc.Command)
	}
	theirs, err := cell.ParseVersions(vc.Body)
	if err != nil {
		return err
	}
	if err := ch.WriteVersions(SupportedLink...); err != nil {
		return err
	}
	v, err := cell.NegotiateVersion(SupportedLink, theirs)
	if err != nil {
		return err
	}
	ch.SetLinkVersion(int(v))

	tlsDigest := sha256.Sum256(keys.TLSCertDER)
	idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(keys.SignPub), keys.IDPriv, keys.IDPub, 24*365*10)
	tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, tlsDigest, keys.SignPriv, nil, 24*365*10)
	certsBody := certs.EncodeCERTS([][2][]byte{
		{{certs.CertTypeIdentityVSigning}, idCert},
		{{certs.CertTypeSigningVTLSCert}, tlsCert},
	})
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certsBody}); err != nil {
		return err
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()}); err != nil {
		return err
	}
	other := [4]byte{}
	if ip4 := ipv4Of(ch.Conn.RemoteAddr()); ip4 != nil {
		copy(other[:], ip4)
	}
	ni := certs.EncodeNetinfo(certs.IPv4(other), []certs.NetIP{certs.IPv4(keys.Advertise)})
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: ni}); err != nil {
		return err
	}
	for {
		c, err := ch.ReadCell()
		if err != nil {
			return err
		}
		switch c.Command {
		case cell.CmdNetinfo:
			return nil
		case cell.CmdCerts, cell.CmdAuthenticate, cell.CmdVpadding, cell.CmdPadding:
			continue
		default:
			return fmt.Errorf("unexpected initiator handshake cell %d", c.Command)
		}
	}
}

func bytesTo32(b []byte) [32]byte {
	var a [32]byte
	copy(a[:], b)
	return a
}

func verifyResponderCERTS(ch *Channel, body []byte, expect ed25519.PublicKey) (ed25519.PublicKey, error) {
	m, err := certs.ParseCERTS(body)
	if err != nil {
		return nil, err
	}
	raw4, ok := m[certs.CertTypeIdentityVSigning]
	if !ok {
		return nil, fmt.Errorf("CERTS missing identity->signing")
	}
	raw5, ok := m[certs.CertTypeSigningVTLSCert]
	if !ok {
		return nil, fmt.Errorf("CERTS missing signing->tls")
	}
	c4, err := certs.ParseEd25519Cert(raw4)
	if err != nil {
		return nil, err
	}
	if err := c4.Verify(c4.SigningKey); err != nil {
		return nil, fmt.Errorf("identity cert: %w", err)
	}
	if expect != nil && !bytes.Equal(expect, c4.SigningKey) {
		return nil, fmt.Errorf("relay ed25519 identity mismatch")
	}
	c5, err := certs.ParseEd25519Cert(raw5)
	if err != nil {
		return nil, err
	}
	if err := c5.Verify(c4.CertifiedKey[:]); err != nil {
		return nil, fmt.Errorf("tls cert: %w", err)
	}
	st := ch.Conn.ConnectionState()
	if len(st.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS peer certificate")
	}
	sum := sha256.Sum256(st.PeerCertificates[0].Raw)
	if sum != c5.CertifiedKey {
		return nil, fmt.Errorf("TLS certificate digest mismatch")
	}
	return c4.SigningKey, nil
}

func ipv4Of(a net.Addr) []byte {
	host, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil
	}
	return v4
}
