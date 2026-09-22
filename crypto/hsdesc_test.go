package crypto

import (
	"crypto/rand"
	"errors"
	"net"
	"strings"
	"testing"
)

func TestHSDescRoundTrip(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var onion, enc [32]byte
	auth := make([]byte, 32)
	if _, err := rand.Read(onion[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(enc[:]); err != nil {
		t.Fatal(err)
	}
	if _, err := rand.Read(auth); err != nil {
		t.Fatal(err)
	}
	want := HSIntro{
		Address:  net.IPv4(172, 28, 0, 21),
		ORPort:   9001,
		OnionKey: onion,
		EncKey:   enc,
		AuthKey:  auth,
	}
	doc, err := BuildHSDesc(rand.Reader, id, want, 7)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ParseHSDesc(doc, id.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Address.Equal(want.Address) || got.ORPort != want.ORPort {
		t.Fatalf("addr %v:%d", got.Address, got.ORPort)
	}
	if got.OnionKey != want.OnionKey || got.EncKey != want.EncKey {
		t.Fatal("ntor keys")
	}
	if len(got.AuthKey) != 32 || string(got.AuthKey) != string(want.AuthKey) {
		t.Fatal("auth key")
	}
}

func TestHSDescBitFlip(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	intro := HSIntro{Address: net.IPv4(10, 0, 0, 1), ORPort: 9001}
	doc, err := BuildHSDesc(rand.Reader, id, intro, 1)
	if err != nil {
		t.Fatal(err)
	}
	_, super, err := parseOuter(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(super) < 40 {
		t.Fatal("short super")
	}
	flipped := append([]byte(nil), super...)
	flipped[20] ^= 0xff
	begin := strings.Index(doc, "-----BEGIN MESSAGE-----")
	endRel := strings.Index(doc[begin:], "-----END MESSAGE-----")
	if begin < 0 || endRel < 0 {
		t.Fatal("pem")
	}
	end := begin + endRel + len("-----END MESSAGE-----")
	tampered := doc[:begin] + pemBlock("MESSAGE", flipped) + doc[end:]
	_, err = ParseHSDesc(tampered, id.Public)
	if !errors.Is(err, ErrHSDescMAC) {
		t.Fatalf("got %v", err)
	}
}
