package crypto

import (
	"bytes"
	"crypto/rand"
	"strings"
	"testing"
	"time"
)

func TestOnionAddressRoundTrip(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := OnionAddress(id.Public)
	if !strings.HasSuffix(addr, ".onion") {
		t.Fatalf("%q", addr)
	}
	label := strings.TrimSuffix(addr, ".onion")
	if len(label) != 56 {
		t.Fatalf("len %d addr %s", len(label), addr)
	}
	got, err := ParseOnionAddress(addr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, id.Public) {
		t.Fatalf("pub mismatch")
	}
	if OnionAddress(got) != addr {
		t.Fatalf("re-encode %s vs %s", OnionAddress(got), addr)
	}
}

func TestOnionAddressExamples(t *testing.T) {
	examples := []string{
		"pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion",
		"sp3k262uwy4r2k3ycr5awluarykdpag6a7y33jxop4cs2lu5uz5sseqd.onion",
		"xa4r2iadxm55fbnqgwwi5mymqdcofiu3w6rpbtqn7b2dyn7mgwj64jyd.onion",
	}
	for _, addr := range examples {
		pub, err := ParseOnionAddress(addr)
		if err != nil {
			t.Fatalf("%s: %v", addr, err)
		}
		if OnionAddress(pub) != addr {
			t.Fatalf("re-encode %s", OnionAddress(pub))
		}
	}
}

func TestParseOnionRejects(t *testing.T) {
	if _, err := ParseOnionAddress("not-an-onion"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := ParseOnionAddress("aaaaaaaaaaaaaaaa.onion"); err == nil {
		t.Fatal("expected v2 reject")
	}
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	addr := []byte(OnionAddress(id.Public))
	addr[0] ^= 0x02
	if _, err := ParseOnionAddress(string(addr)); err == nil {
		t.Fatal("expected checksum fail")
	}
}

func TestBlindDeterministic(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a, err := BlindPublicSim(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	b, err := BlindPublicSim(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) || len(a) != 32 {
		t.Fatalf("blind %x vs %x", a, b)
	}
	fromPriv, err := BlindSecret(id.Private, HSPeriodNum, HSPeriodLength)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, fromPriv) {
		t.Fatal("public vs secret blind mismatch")
	}
	other, err := BlindPublic(id.Public, HSPeriodNum+1, HSPeriodLength)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(a, other) {
		t.Fatal("period did not change blinded key")
	}
}

func TestCredentialSubcredential(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blind, err := BlindPublicSim(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	c1 := Credential(id.Public)
	c2 := Credential(id.Public)
	if !bytes.Equal(c1, c2) || len(c1) != 32 {
		t.Fatalf("credential %x", c1)
	}
	s1 := Subcredential(id.Public, blind)
	s2 := Subcredential(id.Public, blind)
	if !bytes.Equal(s1, s2) || len(s1) != 32 {
		t.Fatalf("subcredential %x", s1)
	}
	if bytes.Equal(c1, s1) {
		t.Fatal("credential equals subcredential")
	}
	other, err := BlindPublic(id.Public, 2, HSPeriodLength)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(s1, Subcredential(id.Public, other)) {
		t.Fatal("subcredential ignored blinded key")
	}
}

func TestHSDescID(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blind, err := BlindPublicSim(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	a := HSDescID(blind)
	b := HSDescID(blind)
	if a != b || len(a) != 64 {
		t.Fatalf("%s", a)
	}
	other, err := BlindPublic(id.Public, 2, HSPeriodLength)
	if err != nil {
		t.Fatal(err)
	}
	if HSDescID(other) == a {
		t.Fatal("period did not change descriptor id")
	}
}

func TestTimePeriodNum(t *testing.T) {
	if TimePeriodNum(time.Unix(0, 0).UTC()) != 0 {
		t.Fatal("epoch")
	}
	// offset 720 minutes; length 1440. unix=(720+1440)*60 is period 1.
	if got := TimePeriodNum(time.Unix((720+1440)*60, 0).UTC()); got != 1 {
		t.Fatalf("got %d", got)
	}
}

func TestHSIndexReplicaAndPeriod(t *testing.T) {
	id, err := GenerateHSIdentity(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	blind, err := BlindPublicSim(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	a := HSIndex(blind, 1, HSPeriodLength, HSPeriodNum)
	b := HSIndex(blind, 2, HSPeriodLength, HSPeriodNum)
	if bytes.Equal(a, b) || len(a) != 32 {
		t.Fatal("replica")
	}
	if hexID := HSDescID(blind); hexID != encodeHex(a) {
		t.Fatal("HSDescID is replica 1")
	}
	if bytes.Equal(NodeIndex(id.Public, DisasterSRV(HSPeriodLength, 1), HSPeriodLength, 1), NodeIndex(id.Public, DisasterSRV(HSPeriodLength, 2), HSPeriodLength, 2)) {
		t.Fatal("node index ignored period")
	}
	if BlindedURLID(blind) == "" || len(BlindedURLID(blind)) < 40 {
		t.Fatal("url id")
	}
}

func encodeHex(b []byte) string {
	const hexdigits = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, v := range b {
		out[i*2] = hexdigits[v>>4]
		out[i*2+1] = hexdigits[v&0x0f]
	}
	return string(out)
}
