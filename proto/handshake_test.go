package proto

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"net"
	"testing"
	"time"

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
