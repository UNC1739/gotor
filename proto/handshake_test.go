package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/certs"
)

func TestLinkHandshake(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	keys := ResponderKeys{
		IDPub:      idPub,
		IDPriv:     idPriv,
		SignPub:    signPub,
		SignPriv:   signPriv,
		TLSCertDER: der,
		Advertise:  [4]byte{127, 0, 0, 1},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		chS := NewChannel(srv)
		errc <- HandshakeResponder(chS, keys)
		_ = chS.Close()
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	chC := NewChannel(cli)
	gotID, err := HandshakeInitiator(chC, idPub)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("responder timeout")
	}
	if string(gotID) != string(idPub) {
		t.Fatal("identity mismatch")
	}
	if chC.LinkVer < 4 {
		t.Fatalf("link ver %d", chC.LinkVer)
	}
	sum := sha256.Sum256(cli.ConnectionState().PeerCertificates[0].Raw)
	want := sha256.Sum256(der)
	if sum != want {
		t.Fatal("peer tls digest")
	}
}

func TestLinkHandshakeRejectsWrongIdentity(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	other, _, _ := ed25519.GenerateKey(rand.Reader)
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}})
		chS := NewChannel(srv)
		_ = HandshakeResponder(chS, keys)
		_ = chS.Close()
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	chC := NewChannel(cli)
	if _, err := HandshakeInitiator(chC, other); err == nil {
		t.Fatal("expected identity mismatch")
	}
}

func TestLinkHandshakeRelayAuth(t *testing.T) {
	rk, ik, tc := handshakeKeys(t)
	ln, errc := serveResponder(t, rk, tc)
	defer ln.Close()
	cli := dialTLS(t, ln.Addr().String())
	defer cli.Close()
	chC := NewChannel(cli)
	got, err := HandshakeInitiatorRelay(chC, rk.IDPub, ik)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitErr(errc); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(rk.IDPub) {
		t.Fatal("identity mismatch")
	}
}

func TestLinkHandshakeRSACrossCert(t *testing.T) {
	rk, _, tc := handshakeKeys(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	rk.RSA = rsaKey
	ln, errc := serveResponder(t, rk, tc)
	defer ln.Close()
	cli := dialTLS(t, ln.Addr().String())
	defer cli.Close()
	chC := NewChannel(cli)
	got, err := HandshakeInitiator(chC, rk.IDPub)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitErr(errc); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(rk.IDPub) {
		t.Fatal("identity mismatch")
	}
}

func TestLinkHandshakeRelayAuthRSA(t *testing.T) {
	rk, ik, tc := handshakeKeys(t)
	var err error
	rk.RSA, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ik.RSA, err = rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	ln, errc := serveResponder(t, rk, tc)
	defer ln.Close()
	cli := dialTLS(t, ln.Addr().String())
	defer cli.Close()
	chC := NewChannel(cli)
	got, err := HandshakeInitiatorRelay(chC, rk.IDPub, ik)
	if err != nil {
		t.Fatal(err)
	}
	if err := waitErr(errc); err != nil {
		t.Fatal(err)
	}
	if string(got) != string(rk.IDPub) {
		t.Fatal("identity mismatch")
	}
}

func TestLinkHandshakeForgedAuthenticate(t *testing.T) {
	rk, ik, tc := handshakeKeys(t)
	ln, errc := serveResponder(t, rk, tc)
	defer ln.Close()
	cli := dialTLS(t, ln.Addr().String())
	defer cli.Close()
	ch := NewChannel(cli)
	if err := relayInitiatorTampered(ch, rk.IDPub, ik); err != nil {
		t.Fatal(err)
	}
	if err := waitErr(errc); err == nil {
		t.Fatal("expected forged AUTHENTICATE to fail")
	}
}

func TestLinkHandshakeCertsWithoutAuth(t *testing.T) {
	rk, ik, tc := handshakeKeys(t)
	ln, errc := serveResponder(t, rk, tc)
	defer ln.Close()
	cli := dialTLS(t, ln.Addr().String())
	defer cli.Close()
	ch := NewChannel(cli)
	if err := ch.WriteVersions(SupportedLink...); err != nil {
		t.Fatal(err)
	}
	vc, err := ch.ReadVersions()
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := cell.ParseVersions(vc.Body)
	if err != nil {
		t.Fatal(err)
	}
	v, err := cell.NegotiateVersion(SupportedLink, theirs)
	if err != nil {
		t.Fatal(err)
	}
	ch.SetLinkVersion(int(v))
	var certsCell, authCell, netinfoCell *cell.Cell
	for certsCell == nil || authCell == nil || netinfoCell == nil {
		c, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		switch c.Command {
		case cell.CmdCerts:
			certsCell = c
		case cell.CmdAuthChallenge:
			authCell = c
		case cell.CmdNetinfo:
			netinfoCell = c
		}
	}
	idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(ik.SignPub), ik.IDPriv, ik.IDPub, 24)
	certsBody := certs.EncodeCERTS([][2][]byte{{{certs.CertTypeIdentityVSigning}, idCert}})
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certsBody}); err != nil {
		t.Fatal(err)
	}
	ni := &cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)}
	if err := ch.WriteCell(ni); err != nil {
		t.Fatal(err)
	}
	if err := waitErr(errc); err == nil {
		t.Fatal("expected CERTS without AUTHENTICATE to fail")
	}
}

func handshakeKeys(t *testing.T) (ResponderKeys, InitiatorKeys, *tls.Certificate) {
	t.Helper()
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	iidPub, iidPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	isignPub, isignPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, [][]byte{{127, 0, 0, 1}})
	if err != nil {
		t.Fatal(err)
	}
	rk := ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der, Advertise: [4]byte{127, 0, 0, 1}}
	ik := InitiatorKeys{IDPub: iidPub, IDPriv: iidPriv, SignPub: isignPub, SignPriv: isignPriv}
	return rk, ik, tc
}

func serveResponder(t *testing.T, keys ResponderKeys, tc *tls.Certificate) (net.Listener, chan error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		chS := NewChannel(srv)
		errc <- HandshakeResponder(chS, keys)
		_ = chS.Close()
	}()
	return ln, errc
}

func dialTLS(t *testing.T, addr string) *tls.Conn {
	t.Helper()
	cli, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	return cli
}

func waitErr(errc chan error) error {
	select {
	case err := <-errc:
		return err
	case <-time.After(5 * time.Second):
		return errTimeout
	}
}

var errTimeout = errString("responder timeout")

type errString string

func (e errString) Error() string { return string(e) }

func relayInitiatorTampered(ch *Channel, expect ed25519.PublicKey, keys InitiatorKeys) error {
	sentVers := cell.Versions(2, SupportedLink...)
	if err := ch.WriteVersions(SupportedLink...); err != nil {
		return err
	}
	vc, err := ch.ReadVersions()
	if err != nil {
		return err
	}
	theirs, err := cell.ParseVersions(vc.Body)
	if err != nil {
		return err
	}
	v, err := cell.NegotiateVersion(SupportedLink, theirs)
	if err != nil {
		return err
	}
	ch.SetLinkVersion(int(v))
	var certsCell, authCell, netinfoCell *cell.Cell
	for certsCell == nil || authCell == nil || netinfoCell == nil {
		c, err := ch.ReadCell()
		if err != nil {
			return err
		}
		switch c.Command {
		case cell.CmdCerts:
			certsCell = c
		case cell.CmdAuthChallenge:
			authCell = c
		case cell.CmdNetinfo:
			netinfoCell = c
		}
	}
	id, err := verifyResponderCERTS(ch, certsCell.Body, expect)
	if err != nil {
		return err
	}
	linkPub, linkPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(keys.SignPub), keys.IDPriv, keys.IDPub, 24*365*10)
	linkCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVLinkAuth, certs.KeyTypeEd25519, bytesTo32(linkPub), keys.SignPriv, nil, 24*365*10)
	certsBody := certs.EncodeCERTS([][2][]byte{
		{{certs.CertTypeIdentityVSigning}, idCert},
		{{certs.CertTypeSigningVLinkAuth}, linkCert},
	})
	initCerts := &cell.Cell{Command: cell.CmdCerts, Body: certsBody}
	if err := ch.WriteCell(initCerts); err != nil {
		return err
	}
	slog := digestLog(vc, ch.CircIDLen, certsCell, authCell)
	clog := digestLog(sentVers, ch.CircIDLen, initCerts)
	authBody, err := buildAuthenticate(ch, keys.IDPub, id, slog, clog, linkPriv)
	if err != nil {
		return err
	}
	authBody[len(authBody)-1] ^= 0xff
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdAuthenticate, Body: authBody}); err != nil {
		return err
	}
	other := [4]byte{127, 0, 0, 1}
	ni := &cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4(other), nil)}
	return ch.WriteCell(ni)
}
