package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
	"time"
)

func TestDirKeyCertRoundTrip(t *testing.T) {
	ident, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignDirKeyCert(ident, signing, "2026-01-01 00:00:00", "2028-01-01 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseDirKeyCerts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 1 {
		t.Fatalf("got %d certs", len(certs))
	}
	if certs[0].Fingerprint != rsaSHA1Hex(&ident.PublicKey) {
		t.Fatalf("fp %s", certs[0].Fingerprint)
	}
	if err := certs[0].ValidAt(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
}

func TestDirKeyCertRejectsTamper(t *testing.T) {
	ident, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignDirKeyCert(ident, signing, "2026-01-01 00:00:00", "2028-01-01 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(raw, "2028-01-01", "2029-01-01", 1)
	if _, err := ParseDirKeyCerts(tampered); err == nil {
		t.Fatal("expected tamper rejection")
	}
}

func TestDirKeyCertExpired(t *testing.T) {
	ident, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := SignDirKeyCert(ident, signing, "2020-01-01 00:00:00", "2020-06-01 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := ParseDirKeyCerts(raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := certs[0].ValidAt(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected expiry")
	}
}
