package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestCreateFastRoundTrip(t *testing.T) {
	x, err := CreateFastHandshake(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	y, kh, skeys, err := CreateFastReply(rand.Reader, x)
	if err != nil {
		t.Fatal(err)
	}
	ckeys, err := CreateFastFinish(x, y, kh)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skeys.Kf, ckeys.Kf) || !bytes.Equal(skeys.Kb, ckeys.Kb) {
		t.Fatal("cipher keys")
	}
	if !bytes.Equal(skeys.Df, ckeys.Df) || !bytes.Equal(skeys.Db, ckeys.Db) {
		t.Fatal("digest keys")
	}
}

func TestCreateFastBadKH(t *testing.T) {
	x, _ := CreateFastHandshake(rand.Reader)
	y, kh, _, err := CreateFastReply(rand.Reader, x)
	if err != nil {
		t.Fatal(err)
	}
	kh[0] ^= 0xff
	if _, err := CreateFastFinish(x, y, kh); err == nil {
		t.Fatal("expected KH mismatch")
	}
}

func TestKDFTorLength(t *testing.T) {
	out := KDFTor([]byte("k0"), 92)
	if len(out) != 92 {
		t.Fatalf("len %d", len(out))
	}
}
