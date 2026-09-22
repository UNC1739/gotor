package crypto

import (
	"bytes"
	"crypto/rand"
	"crypto/sha1"
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

func TestKDFTorMatchesSHA1Counter(t *testing.T) {
	k0 := []byte("k0")
	out := KDFTor(k0, 40)
	h0 := sha1.Sum(append(append([]byte{}, k0...), 0))
	h1 := sha1.Sum(append(append([]byte{}, k0...), 1))
	if !bytes.Equal(out[:20], h0[:]) || !bytes.Equal(out[20:], h1[:]) {
		t.Fatal("KDF-TOR counter")
	}
}

func TestCreateFastBadLengths(t *testing.T) {
	if _, _, _, err := CreateFastReply(rand.Reader, []byte{1}); err == nil {
		t.Fatal("short X")
	}
	if _, err := CreateFastFinish(make([]byte, 19), make([]byte, 20), make([]byte, 20)); err == nil {
		t.Fatal("short X finish")
	}
	if _, err := CreateFastFinish(make([]byte, 20), make([]byte, 19), make([]byte, 20)); err == nil {
		t.Fatal("short Y finish")
	}
	if _, err := CreateFastFinish(make([]byte, 20), make([]byte, 20), make([]byte, 19)); err == nil {
		t.Fatal("short KH finish")
	}
}

func TestCreateFastKeyLayout(t *testing.T) {
	x := bytes.Repeat([]byte{1}, 20)
	y := bytes.Repeat([]byte{2}, 20)
	k0 := append(append([]byte{}, x...), y...)
	keys := keysFromTOR(k0)
	want := KDFTor(k0, 92)
	if !bytes.Equal(keys.KH, want[0:20]) || !bytes.Equal(keys.Df, want[20:40]) || !bytes.Equal(keys.Db, want[40:60]) {
		t.Fatal("digest layout")
	}
	if !bytes.Equal(keys.Kf, want[60:76]) || !bytes.Equal(keys.Kb, want[76:92]) {
		t.Fatal("cipher layout")
	}
}

func TestCreateFastRNGFailure(t *testing.T) {
	if _, err := CreateFastHandshake(bytes.NewReader(nil)); err == nil {
		t.Fatal("handshake rng")
	}
	x := make([]byte, 20)
	if _, _, _, err := CreateFastReply(bytes.NewReader(nil), x); err == nil {
		t.Fatal("reply rng")
	}
}

