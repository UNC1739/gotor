package crypto

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"testing"
)

func TestNtorRoundTrip(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [20]byte
	id[0] = 0xab
	srv := &NtorServer{ID: id, Key: serverKey}
	hs, st, err := NtorClientHandshake(rand.Reader, id, serverKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != NtorHLen {
		t.Fatalf("hs len %d", len(hs))
	}
	reply, skeys, err := srv.Reply(rand.Reader, hs)
	if err != nil {
		t.Fatal(err)
	}
	ckeys, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(skeys.Kf, ckeys.Kf) || !bytes.Equal(skeys.Kb, ckeys.Kb) {
		t.Fatal("cipher keys differ")
	}
	if !bytes.Equal(skeys.Df, ckeys.Df) || !bytes.Equal(skeys.Db, ckeys.Db) {
		t.Fatal("digest keys differ")
	}
	if !bytes.Equal(skeys.KH, ckeys.KH) {
		t.Fatal("KH differs")
	}
}

func TestNtorRejectsBadAuth(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	var id [20]byte
	srv := &NtorServer{ID: id, Key: serverKey}
	hs, st, _ := NtorClientHandshake(rand.Reader, id, serverKey.Public)
	reply, _, err := srv.Reply(rand.Reader, hs)
	if err != nil {
		t.Fatal(err)
	}
	reply[40] ^= 0xff
	if _, err := st.Finish(reply); err == nil {
		t.Fatal("expected auth failure")
	}
}

func TestNtorRejectsBadNodeID(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	var id, other [20]byte
	id[0] = 1
	other[0] = 2
	srv := &NtorServer{ID: id, Key: serverKey}
	hs, _, _ := NtorClientHandshake(rand.Reader, other, serverKey.Public)
	if _, _, err := srv.Reply(rand.Reader, hs); err != ErrNtorID {
		t.Fatalf("got %v", err)
	}
}

func TestNtorRejectsBadKeyID(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	otherKey, _ := GenerateKeyPair(rand.Reader)
	var id [20]byte
	srv := &NtorServer{ID: id, Key: serverKey}
	hs, _, _ := NtorClientHandshake(rand.Reader, id, otherKey.Public)
	if _, _, err := srv.Reply(rand.Reader, hs); err != ErrNtorKey {
		t.Fatalf("got %v", err)
	}
}

func TestNtorShortInputs(t *testing.T) {
	var id [20]byte
	var pub [32]byte
	st := &NtorClientState{ID: id, B: pub, X: &KeyPair{}}
	if _, err := st.Finish([]byte{1, 2, 3}); err == nil {
		t.Fatal("expected short reply error")
	}
	srv := &NtorServer{ID: id, Key: &KeyPair{}}
	if _, _, err := srv.Reply(rand.Reader, []byte{1}); err == nil {
		t.Fatal("expected short handshake error")
	}
}

func TestKDFMatchesSpecRecurrence(t *testing.T) {
	seed := bytes.Repeat([]byte{0x0b}, 32)
	got, err := expandKeys(seed)
	if err != nil {
		t.Fatal(err)
	}
	want := hkdfSpec(seed, 92)
	if !bytes.Equal(got.Df, want[0:20]) || !bytes.Equal(got.Db, want[20:40]) {
		t.Fatal("digest partition mismatch")
	}
	if !bytes.Equal(got.Kf, want[40:56]) || !bytes.Equal(got.Kb, want[56:72]) {
		t.Fatal("cipher partition mismatch")
	}
	if !bytes.Equal(got.KH, want[72:92]) {
		t.Fatal("KH partition mismatch")
	}
}

func hkdfSpec(keySeed []byte, n int) []byte {
	var out []byte
	var prev []byte
	info := []byte(mExpand)
	for i := 1; len(out) < n; i++ {
		m := hmac.New(sha256.New, keySeed)
		m.Write(prev)
		m.Write(info)
		m.Write([]byte{byte(i)})
		prev = m.Sum(nil)
		out = append(out, prev...)
	}
	return out[:n]
}
