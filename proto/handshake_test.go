package proto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
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

func TestLinkHandshakeNilExpectID(t *testing.T) {
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
	keys := ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der, Advertise: [4]byte{127, 0, 0, 1}}
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
	gotID, err := HandshakeInitiator(chC, nil)
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
		t.Fatal("identity")
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

func TestLinkHandshakeRejectsMissingCERTS(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS(nil)})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected missing CERTS")
	}
}

func TestLinkHandshakeSkipsPadding(t *testing.T) {
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
		if _, err := chS.ReadVersions(); err != nil {
			errc <- err
			return
		}
		if err := chS.WriteVersions(4, 5); err != nil {
			errc <- err
			return
		}
		chS.SetLinkVersion(4)
		if err := chS.WriteCell(cell.Padding()); err != nil {
			errc <- err
			return
		}
		tlsDigest := sha256.Sum256(der)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), idPriv, idPub, 24)
		tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, tlsDigest, signPriv, nil, 24)
		if err := chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, idCert},
			{{certs.CertTypeSigningVTLSCert}, tlsCert},
		})}); err != nil {
			errc <- err
			return
		}
		if err := chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()}); err != nil {
			errc <- err
			return
		}
		if err := chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)}); err != nil {
			errc <- err
			return
		}
		for {
			got, err := chS.ReadCell()
			if err != nil {
				errc <- err
				return
			}
			if got.Command == cell.CmdNetinfo {
				errc <- nil
				return
			}
		}
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), idPub); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}


func TestLinkHandshakeRejectsUnexpectedCell(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		_ = chS.WriteCell(cell.Destroy(0, 1))
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected unexpected cell")
	}
}

func TestLinkHandshakeRejectsMissingType5(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), idPriv, idPub, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{{{certs.CertTypeIdentityVSigning}, idCert}})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected missing type 5")
	}
}

func TestLinkHandshakeRejectsTLSDigestMismatch(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), idPriv, idPub, 24)
		var fake [32]byte
		tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, fake, signPriv, nil, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, idCert},
			{{certs.CertTypeSigningVTLSCert}, tlsCert},
		})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected TLS digest mismatch")
	}
}

func TestHandshakeResponderRejectsNonVersions(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der, Advertise: [4]byte{127, 0, 0, 1}}
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
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := NewChannel(cli).WriteCell(cell.Destroy(0, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected non-VERSIONS")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeResponderRejectsNoCommonVersion(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := NewChannel(cli).WriteVersions(3); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected no common version")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeResponderSkipsInitiatorPadding(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	keys := ResponderKeys{IDPub: idPub, IDPriv: idPriv, SignPub: signPub, SignPriv: signPriv, TLSCertDER: der, Advertise: [4]byte{127, 0, 0, 1}}
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
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadVersions(); err != nil {
		t.Fatal(err)
	}
	ch.SetLinkVersion(4)
	var sawNetinfo bool
	for !sawNetinfo {
		c, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if c.Command == cell.CmdNetinfo {
			sawNetinfo = true
		}
	}
	if err := ch.WriteCell(cell.Padding()); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(cell.Vpadding([]byte{1, 2, 3})); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdAuthenticate, Body: []byte{0}}); err != nil {
		t.Fatal(err)
	}
	if err := ch.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeResponderRejectsUnexpectedCell(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadVersions(); err != nil {
		t.Fatal(err)
	}
	ch.SetLinkVersion(4)
	for {
		c, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if c.Command == cell.CmdNetinfo {
			break
		}
	}
	if err := ch.WriteCell(cell.Destroy(0, 1)); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected unexpected cell")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeInitiatorRejectsNoCommonVersion(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(3)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected no common version")
	}
}

func TestHandshakeInitiatorRejectsOddVersions(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdVersions, Body: []byte{0, 4, 0}})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected odd VERSIONS")
	}
}

func TestHandshakeInitiatorRejectsNonVersions(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_ = NewChannel(srv).WriteCell(cell.Destroy(0, 1))
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected non-VERSIONS")
	}
}

func TestHandshakeInitiatorRejectsMalformedCERTS(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: []byte{1}})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected malformed CERTS")
	}
}

func TestHandshakeInitiatorRejectsGarbageType5(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), idPriv, idPub, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, idCert},
			{{certs.CertTypeSigningVTLSCert}, []byte{1, 2, 3}},
		})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected garbage type 5")
	}
}

func TestHandshakeInitiatorRejectsBadType5Sig(t *testing.T) {
	idPub, idPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		tlsDigest := sha256.Sum256(der)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), idPriv, idPub, 24)
		tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, tlsDigest, otherPriv, nil, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, idCert},
			{{certs.CertTypeSigningVTLSCert}, tlsCert},
		})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected bad type 5 signature")
	}
}

func TestHandshakeResponderRejectsOddVersions(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if err := NewChannel(cli).WriteCell(&cell.Cell{Command: cell.CmdVersions, Body: []byte{0, 4, 0}}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected odd VERSIONS")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeInitiatorReadVersionsError(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_ = srv.Handshake()
		_ = srv.Close()
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected read error")
	}
}

func TestHandshakeInitiatorWriteVersionsError(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_ = srv.Handshake()
		_ = srv.Close()
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected write error")
	}
}



func TestHandshakeInitiatorTruncatedAfterVersions(t *testing.T) {
	tc, _, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		_ = srv.Close()
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected truncated after VERSIONS")
	}
}

func TestHandshakeResponderWriteVersionsError(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected write error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}



func TestHandshakeResponderWriteCERTSError(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadVersions(); err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected CERTS write error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeResponderWriteAuthError(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadVersions(); err != nil {
		t.Fatal(err)
	}
	ch.SetLinkVersion(4)
	for {
		c, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if c.Command == cell.CmdCerts {
			break
		}
	}
	_ = cli.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected AUTH_CHALLENGE write error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}

func TestHandshakeResponderWriteNetinfoError(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	ch := NewChannel(cli)
	if err := ch.WriteVersions(4, 5); err != nil {
		t.Fatal(err)
	}
	if _, err := ch.ReadVersions(); err != nil {
		t.Fatal(err)
	}
	ch.SetLinkVersion(4)
	for {
		c, err := ch.ReadCell()
		if err != nil {
			t.Fatal(err)
		}
		if c.Command == cell.CmdAuthChallenge {
			break
		}
	}
	_ = cli.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected NETINFO write error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}



func TestHandshakeResponderReadVersionsError(t *testing.T) {
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
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
	errc := make(chan error, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			errc <- err
			return
		}
		srv := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*tc}, MinVersion: tls.VersionTLS12})
		errc <- HandshakeResponder(NewChannel(srv), keys)
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12})
	if err != nil {
		t.Fatal(err)
	}
	_ = cli.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("expected read error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout")
	}
}




func TestIPv4Of(t *testing.T) {
	got := ipv4Of(fakeAddr("1.2.3.4:9001"))
	if !bytes.Equal(got, []byte{1, 2, 3, 4}) {
		t.Fatalf("%v", got)
	}
	if ipv4Of(fakeAddr("not-an-addr")) != nil {
		t.Fatal("unsplit")
	}
	if ipv4Of(fakeAddr("hostname:80")) != nil {
		t.Fatal("hostname")
	}
	if ipv4Of(fakeAddr("[::1]:80")) != nil {
		t.Fatal("ipv6")
	}
}

func TestLinkHandshakeRejectsGarbageType4(t *testing.T) {
	_, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		tlsDigest := sha256.Sum256(der)
		tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, tlsDigest, signPriv, nil, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, []byte{1, 2, 3}},
			{{certs.CertTypeSigningVTLSCert}, tlsCert},
		})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected garbage type 4")
	}
}

func TestLinkHandshakeRejectsBadType4Sig(t *testing.T) {
	idPub, _, _ := ed25519.GenerateKey(rand.Reader)
	_, otherPriv, _ := ed25519.GenerateKey(rand.Reader)
	signPub, signPriv, _ := ed25519.GenerateKey(rand.Reader)
	tc, der, err := certs.SelfSignedTLS([]string{"localhost"}, nil)
	if err != nil {
		t.Fatal(err)
	}
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
		_, _ = chS.ReadVersions()
		_ = chS.WriteVersions(4, 5)
		chS.SetLinkVersion(4)
		tlsDigest := sha256.Sum256(der)
		idCert := certs.EncodeEd25519Cert(certs.CertTypeIdentityVSigning, certs.KeyTypeEd25519, bytesTo32(signPub), otherPriv, idPub, 24)
		tlsCert := certs.EncodeEd25519Cert(certs.CertTypeSigningVTLSCert, certs.KeyTypeSHA256X509, tlsDigest, signPriv, nil, 24)
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdCerts, Body: certs.EncodeCERTS([][2][]byte{
			{{certs.CertTypeIdentityVSigning}, idCert},
			{{certs.CertTypeSigningVTLSCert}, tlsCert},
		})})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdAuthChallenge, Body: certs.EncodeAuthChallenge()})
		_ = chS.WriteCell(&cell.Cell{Command: cell.CmdNetinfo, Body: certs.EncodeNetinfo(certs.IPv4([4]byte{127, 0, 0, 1}), nil)})
	}()
	cli, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	if _, err := HandshakeInitiator(NewChannel(cli), nil); err == nil {
		t.Fatal("expected bad type 4 signature")
	}
}


type fakeAddr string

func (f fakeAddr) Network() string { return "tcp" }
func (f fakeAddr) String() string  { return string(f) }



