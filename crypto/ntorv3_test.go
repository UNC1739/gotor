package crypto

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/curve25519"

	"github.com/adam/gotor/cell"
)

func TestNtorV3RoundTripEmpty(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	id[0] = 0xab
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, st, err := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(hs) != NtorV3MinH {
		t.Fatalf("hs len %d", len(hs))
	}
	reply, skeys, gotExtra, err := srv.Reply(rand.Reader, hs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(gotExtra) != 0 {
		t.Fatalf("client extra %d", len(gotExtra))
	}
	if len(reply) != NtorV3MinR {
		t.Fatalf("reply len %d", len(reply))
	}
	ckeys, sm, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	if len(sm) != 0 {
		t.Fatalf("server extra %d", len(sm))
	}
	assertSameKeys(t, skeys, ckeys)
}

func TestNtorV3ExtraData(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	id[1] = 0xcd
	cm := []byte("client extra")
	sm := []byte("server extra")
	ver := []byte("xyzzy")
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, st, err := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, cm, ver)
	if err != nil {
		t.Fatal(err)
	}
	reply, skeys, gotCM, err := srv.Reply(rand.Reader, hs, sm, ver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCM, cm) {
		t.Fatalf("cm %q", gotCM)
	}
	ckeys, gotSM, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSM, sm) {
		t.Fatalf("sm %q", gotSM)
	}
	assertSameKeys(t, skeys, ckeys)
}

func TestNtorV3CCExtra(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	id[2] = 0xef
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, st, err := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, EncodeCCRequest(), []byte(NtorV3CircuitVerify))
	if err != nil {
		t.Fatal(err)
	}
	reply, skeys, gotCM, err := srv.Reply(rand.Reader, hs, nil, []byte(NtorV3CircuitVerify))
	if err != nil {
		t.Fatal(err)
	}
	if !HasCCRequest(gotCM) {
		t.Fatal("missing CC request")
	}
	ckeys, sm, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	inc, ok := CCSendmeIncFrom(sm)
	if !ok || inc != CCSendmeInc {
		t.Fatalf("sendme_inc %d ok=%v", inc, ok)
	}
	assertSameKeys(t, skeys, ckeys)
}

func TestCCExtRoundTrip(t *testing.T) {
	if !HasCCRequest(EncodeCCRequest()) {
		t.Fatal("request")
	}
	inc, ok := CCSendmeIncFrom(EncodeCCResponse(31))
	if !ok || inc != 31 {
		t.Fatalf("%d %v", inc, ok)
	}
	if HasCCRequest(nil) || CCResponseIfRequested(nil) != nil {
		t.Fatal("empty")
	}
}

func TestNtorV3RejectsBadAuth(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	var id [32]byte
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, st, _ := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, nil, nil)
	reply, _, _, err := srv.Reply(rand.Reader, hs, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	reply[40] ^= 0xff
	if _, _, err := st.Finish(reply); err != ErrNtorAuth {
		t.Fatalf("got %v", err)
	}
}

func TestNtorV3RejectsBadMAC(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	var id [32]byte
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, _, _ := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, []byte("x"), nil)
	hs[len(hs)-1] ^= 0xff
	if _, _, _, err := srv.Reply(rand.Reader, hs, nil, nil); err != ErrNtorV3MAC {
		t.Fatalf("got %v", err)
	}
}

func TestNtorV3RejectsBadNodeID(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	var id, other [32]byte
	id[0] = 1
	other[0] = 2
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, _, _ := NtorV3ClientHandshake(rand.Reader, other, serverKey.Public, nil, nil)
	if _, _, _, err := srv.Reply(rand.Reader, hs, nil, nil); err != ErrNtorID {
		t.Fatalf("got %v", err)
	}
}

func TestNtorV3RejectsBadKeyID(t *testing.T) {
	serverKey, _ := GenerateKeyPair(rand.Reader)
	otherKey, _ := GenerateKeyPair(rand.Reader)
	var id [32]byte
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, _, _ := NtorV3ClientHandshake(rand.Reader, id, otherKey.Public, nil, nil)
	if _, _, _, err := srv.Reply(rand.Reader, hs, nil, nil); err != ErrNtorKey {
		t.Fatalf("got %v", err)
	}
}

func TestNtorV3ShortInputs(t *testing.T) {
	var id [32]byte
	st := &NtorV3ClientState{ID: id, X: &KeyPair{}}
	if _, _, err := st.Finish([]byte{1, 2, 3}); err != ErrNtorV3Len {
		t.Fatalf("got %v", err)
	}
	srv := &NtorV3Server{ID: id, Key: &KeyPair{}}
	if _, _, _, err := srv.Reply(rand.Reader, []byte{1}, nil, nil); err != ErrNtorV3Len {
		t.Fatalf("got %v", err)
	}
}

func TestNtorV3RejectsNtorHandshake(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id20 [20]byte
	id20[0] = 1
	hs, _, err := NtorClientHandshake(rand.Reader, id20, serverKey.Public)
	if err != nil {
		t.Fatal(err)
	}
	var id32 [32]byte
	copy(id32[:], id20[:])
	srv := &NtorV3Server{ID: id32, Key: serverKey}
	if _, _, _, err := srv.Reply(rand.Reader, hs, nil, nil); err == nil {
		t.Fatal("expected ntor onionskin rejected as ntor-v3")
	}
}

func TestNtorV3HopSeal(t *testing.T) {
	serverKey, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var id [32]byte
	id[2] = 0xef
	srv := &NtorV3Server{ID: id, Key: serverKey}
	hs, st, err := NtorV3ClientHandshake(rand.Reader, id, serverKey.Public, nil, []byte(NtorV3CircuitVerify))
	if err != nil {
		t.Fatal(err)
	}
	reply, skeys, _, err := srv.Reply(rand.Reader, hs, nil, []byte(NtorV3CircuitVerify))
	if err != nil {
		t.Fatal(err)
	}
	ckeys, _, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	clientHop, err := NewHop(ckeys)
	if err != nil {
		t.Fatal(err)
	}
	relayHop, err := NewHop(skeys)
	if err != nil {
		t.Fatal(err)
	}
	body := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte("127.0.0.1:80")})
	clientHop.SealForward(body)
	relayHop.DecryptForward(body)
	if !relayHop.RecognizeForward(body) {
		t.Fatal("relay did not recognize")
	}
	got, err := cell.DecodeRelay(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.RelayBegin || !bytes.Contains(got.Data, []byte("127.0.0.1:80")) {
		t.Fatalf("%+v", got)
	}
	back := cell.EncodeRelay(cell.Relay{Command: cell.RelayConnected, StreamID: 1, Data: make([]byte, 8)})
	relayHop.SealBackward(back)
	clientHop.DecryptBackward(back)
	if !clientHop.RecognizeBackward(back) {
		t.Fatal("client did not recognize")
	}
}

func TestNtorV3ArtiVector(t *testing.T) {
	b := mustKP(t, "4051daa5921cfa2a1c27b08451324919538e79e788a81b38cbed097a5dff454a")
	x := mustKP(t, "b825a3719147bcbe5fb1d0b0fcb9c09e51948048e2e3283d2ab7b45b5ef38b49")
	y := mustKP(t, "4865a5b7689dafd978f529291c7171bc159be076b92186405d13220b80e2a053")
	idRaw := mustHex(t, "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2")
	var id [32]byte
	copy(id[:], idRaw)
	cm := mustHex(t, "68656c6c6f20776f726c64")
	sm := mustHex(t, "486f6c61204d756e646f")
	ver := mustHex(t, "78797a7a79")
	wantHS := mustHex(t, "9fad2af287ef942632833d21f946c6260c33fae6172b60006e86e4a6911753a2f8307a2bc1870b00b828bb74dbb8fd88e632a6375ab3bcd1ae706aaa8b6cdd1d252fe9ae91264c91d4ecb8501f79d0387e34ad8ca0f7c995184f7d11d5da4f463bebd9151fd3b47c180abc9e044d53565f04d82bbb3bebed3d06cea65db8be9c72b68cd461942088502f67")
	wantReply := mustHex(t, "4bf4814326fdab45ad5184f5518bd7fae25dc59374062698201a50a22954246d2fc5f8773ca824542bc6cf6f57c7c29bbf4e5476461ab130c5b18ab0a91276651202c3e1e87c0d32054c")
	wantKS := mustHex(t, "9c19b631fd94ed86a817e01f6c80b0743a43f5faebd39cfaa8b00fa8bcc65c3bfeaa403d91acbd68a821bf6ee8504602b094a254392a07737d5662768c7a9fb1b2814bb34780eaee6e867c773e28c212ead563e98a1cd5d5b4576f5ee61c59bde025ff2851bb19b721421694f263818e3531e43a9e4e3e2c661e2ad547d8984caa28ebecd3e4525452299be26b9185a20a90ce1eac20a91f2832d731b54502b09749b5a2a2949292f8cfcbeffb790c7790ed935a9d251e7e336148ea83b063a5618fcff674a44581585fd22077ca0e52c59a24347a38d1a1ceebddbf238541f226b8f88d0fb9c07a1bcd2ea764bbbb5dacdaf5312a14c0b9e4f06309b0333b4a")

	hs, st, err := ntorV3ClientFromX(x, id, b.Public, cm, ver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hs, wantHS) {
		t.Fatalf("client handshake\n got %x\nwant %x", hs, wantHS)
	}
	srv := &NtorV3Server{ID: id, Key: b}
	reply, skeys, gotCM, err := srv.replyWithY(y, hs, sm, ver)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotCM, cm) {
		t.Fatalf("cm %x", gotCM)
	}
	if !bytes.Equal(reply, wantReply) {
		t.Fatalf("server handshake\n got %x\nwant %x", reply, wantReply)
	}
	ckeys, gotSM, err := st.Finish(reply)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotSM, sm) {
		t.Fatalf("sm %x", gotSM)
	}
	assertSameKeys(t, skeys, ckeys)
	if !bytes.Equal(ckeys.Df, wantKS[0:20]) || !bytes.Equal(ckeys.Db, wantKS[20:40]) {
		t.Fatal("digest partition")
	}
	if !bytes.Equal(ckeys.Kf, wantKS[40:56]) || !bytes.Equal(ckeys.Kb, wantKS[56:72]) {
		t.Fatal("cipher partition")
	}
	if !bytes.Equal(ckeys.KH, wantKS[72:92]) {
		t.Fatal("KH partition")
	}
}

func assertSameKeys(t *testing.T, a, b *CircuitKeys) {
	t.Helper()
	if !bytes.Equal(a.Kf, b.Kf) || !bytes.Equal(a.Kb, b.Kb) {
		t.Fatal("cipher keys differ")
	}
	if !bytes.Equal(a.Df, b.Df) || !bytes.Equal(a.Db, b.Db) {
		t.Fatal("digest keys differ")
	}
	if !bytes.Equal(a.KH, b.KH) {
		t.Fatal("KH differs")
	}
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mustKP(t *testing.T, privHex string) *KeyPair {
	t.Helper()
	raw := mustHex(t, privHex)
	kp := &KeyPair{}
	copy(kp.Private[:], raw)
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		t.Fatal(err)
	}
	copy(kp.Public[:], pub)
	return kp
}
