package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func TestConsensusSignatureRoundTrip(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	body := "network-status-version 3\nvote-status consensus\ndirectory-footer\n"
	signed, err := SignConsensus(body, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsensus(signed, &key.PublicKey); err != nil {
		t.Fatal(err)
	}
}

func TestConsensusSignatureRejectsTamper(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignConsensus("network-status-version 3\nr flipped 1\ndirectory-footer\n", key)
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(signed, "flipped", "FLIPPED", 1)
	if err := VerifyConsensus(tampered, &key.PublicKey); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestConsensusSignatureRejectsMissing(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsensus("network-status-version 3\ndirectory-footer\n", &key.PublicKey); err == nil {
		t.Fatal("expected missing signature rejection")
	}
}

func TestConsensusSignatureRejectsWrongKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := SignConsensus("network-status-version 3\ndirectory-footer\n", key)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyConsensus(signed, &other.PublicKey); err == nil {
		t.Fatal("expected wrong-key rejection")
	}
}
