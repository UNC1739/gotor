package crypto

import (
	"bytes"
	"hash"
	"testing"

	"github.com/adam/gotor/cell"
)

func TestOnionLayers(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	msg := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte("127.0.0.1:80")})
	OnionEncrypt(hops, 2, msg)

	body := append([]byte(nil), msg...)
	for i := range 3 {
		exitHops[i].DecryptForward(body)
		rec := exitHops[i].RecognizeForward(body)
		if i < 2 && rec {
			t.Fatalf("hop %d unexpectedly recognized", i)
		}
		if i == 2 && !rec {
			t.Fatal("exit did not recognize")
		}
	}
	got, err := cell.DecodeRelay(body)
	if err != nil {
		t.Fatal(err)
	}
	if got.Command != cell.RelayBegin || !bytes.Contains(got.Data, []byte("127.0.0.1:80")) {
		t.Fatalf("%+v", got)
	}

	reply := cell.EncodeRelay(cell.Relay{Command: cell.RelayConnected, StreamID: 1, Data: make([]byte, 8)})
	exitHops[2].SealBackward(reply)
	exitHops[1].EncryptBackward(reply)
	exitHops[0].EncryptBackward(reply)
	hop, ok := OnionDecrypt(hops, reply)
	if !ok || hop != 2 {
		t.Fatalf("client recognize hop=%d ok=%v", hop, ok)
	}
}

func TestOnionLayersMany(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	for i := range 50 {
		payload := []byte{byte(i), byte(i + 1), byte(i + 2)}
		msg := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: payload})
		OnionEncrypt(hops, 2, msg)
		body := append([]byte(nil), msg...)
		for j := range 2 {
			exitHops[j].DecryptForward(body)
			if exitHops[j].RecognizeForward(body) {
				t.Fatalf("hop %d recognized cell %d", j, i)
			}
		}
		exitHops[2].DecryptForward(body)
		if !exitHops[2].RecognizeForward(body) {
			t.Fatalf("exit missed cell %d", i)
		}
		got, err := cell.DecodeRelay(body)
		if err != nil || !bytes.Equal(got.Data, payload) {
			t.Fatalf("cell %d: %+v %v", i, got, err)
		}
	}
}

func TestOnionDecryptUnrecognized(t *testing.T) {
	hops, _ := pairedHops(t, 3)
	junk := make([]byte, cell.BodyLen)
	hop, ok := OnionDecrypt(hops, junk)
	if ok || hop != -1 {
		t.Fatalf("hop=%d ok=%v", hop, ok)
	}
}

func TestMiddleHopRecognized(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	msg := cell.EncodeRelay(cell.Relay{Command: cell.RelayExtend2, StreamID: 0, Data: []byte("extend")})
	OnionEncrypt(hops, 1, msg)
	body := append([]byte(nil), msg...)
	exitHops[0].DecryptForward(body)
	if exitHops[0].RecognizeForward(body) {
		t.Fatal("guard recognized middle cell")
	}
	exitHops[1].DecryptForward(body)
	if !exitHops[1].RecognizeForward(body) {
		t.Fatal("middle did not recognize")
	}
}

func TestFalseRecognizedDoesNotDesyncDigest(t *testing.T) {
	k := dummyKeys(9)
	a, err := NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	c1 := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("one")})
	a.SealForward(c1)
	b.DecryptForward(c1)
	if !b.RecognizeForward(c1) {
		t.Fatal("first cell")
	}
	junk := make([]byte, cell.BodyLen)
	if b.RecognizeForward(junk) {
		t.Fatal("junk recognized")
	}
	junk[1] = 1
	if b.RecognizeForward(junk) {
		t.Fatal("nonzero recognized field")
	}
	c2 := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("two")})
	a.SealForward(c2)
	b.DecryptForward(c2)
	if !b.RecognizeForward(c2) {
		t.Fatal("digest desynced after false recognized")
	}
	got, err := cell.DecodeRelay(c2)
	if err != nil || string(got.Data) != "two" {
		t.Fatalf("%+v %v", got, err)
	}
}

func TestSequentialRelayCells(t *testing.T) {
	k := dummyKeys(3)
	snd, _ := NewHop(k)
	rcv, _ := NewHop(k)
	for i := range 50 {
		payload := []byte{byte(i)}
		body := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 4, Data: payload})
		snd.SealForward(body)
		rcv.DecryptForward(body)
		if !rcv.RecognizeForward(body) {
			t.Fatalf("cell %d not recognized", i)
		}
		msg, err := cell.DecodeRelay(body)
		if err != nil || len(msg.Data) != 1 || msg.Data[0] != byte(i) {
			t.Fatalf("cell %d: %+v %v", i, msg, err)
		}
	}
}

func TestSequentialInboundCells(t *testing.T) {
	k := dummyKeys(3)
	snd, _ := NewHop(k)
	rcv, _ := NewHop(k)
	for i := range 50 {
		payload := []byte{byte(i)}
		body := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 4, Data: payload})
		snd.SealBackward(body)
		rcv.DecryptBackward(body)
		if !rcv.RecognizeBackward(body) {
			t.Fatalf("cell %d not recognized", i)
		}
		msg, err := cell.DecodeRelay(body)
		if err != nil || len(msg.Data) != 1 || msg.Data[0] != byte(i) {
			t.Fatalf("cell %d: %+v %v", i, msg, err)
		}
	}
	if !bytes.Equal(snd.BackwardDigest(), rcv.BackwardDigest()) || len(snd.BackwardDigest()) != 20 {
		t.Fatal("backward digest")
	}
}

func TestSendmeV1DigestAgrees(t *testing.T) {
	k := dummyKeys(3)
	snd, _ := NewHop(k)
	rcv, _ := NewHop(k)
	begin := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte("127.0.0.1:80")})
	snd.SealForward(begin)
	rcv.DecryptForward(begin)
	if !rcv.RecognizeForward(begin) {
		t.Fatal("BEGIN")
	}
	var want []byte
	for i := range cell.CircWindowInc {
		body := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte{byte(i)}})
		snd.SealForward(body)
		if i == cell.CircWindowInc-1 {
			want = append([]byte(nil), snd.ForwardDigest()...)
		}
		rcv.DecryptForward(body)
		if !rcv.RecognizeForward(body) {
			t.Fatalf("DATA %d", i)
		}
	}
	got := rcv.ForwardDigest()
	if !bytes.Equal(want, got) || len(want) != 20 {
		t.Fatalf("digest mismatch want=%x got=%x", want, got)
	}
}

func TestClientStopsAtOriginatingHop(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	for dest := range 3 {
		reply := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte{byte(dest)}})
		exitHops[dest].SealBackward(reply)
		for i := dest - 1; i >= 0; i-- {
			exitHops[i].EncryptBackward(reply)
		}
		hop, ok := OnionDecrypt(hops, reply)
		if !ok || hop != dest {
			t.Fatalf("dest %d -> hop %d ok=%v", dest, hop, ok)
		}
	}
}

func TestFalseRecognizedBackwardDoesNotDesyncDigest(t *testing.T) {
	k := dummyKeys(9)
	a, err := NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewHop(k)
	if err != nil {
		t.Fatal(err)
	}
	c1 := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("one")})
	a.SealBackward(c1)
	b.DecryptBackward(c1)
	if !b.RecognizeBackward(c1) {
		t.Fatal("first cell")
	}
	junk := make([]byte, cell.BodyLen)
	if b.RecognizeBackward(junk) {
		t.Fatal("junk recognized")
	}
	junk[1] = 1
	if b.RecognizeBackward(junk) {
		t.Fatal("nonzero recognized field")
	}
	c2 := cell.EncodeRelay(cell.Relay{Command: cell.RelayData, StreamID: 1, Data: []byte("two")})
	a.SealBackward(c2)
	b.DecryptBackward(c2)
	if !b.RecognizeBackward(c2) {
		t.Fatal("digest desynced after false recognized")
	}
}

func TestNewHopBadKeyLength(t *testing.T) {
	k := dummyKeys(1)
	k.Kf = []byte{1}
	if _, err := NewHop(k); err == nil {
		t.Fatal("short Kf")
	}
	k = dummyKeys(1)
	k.Kb = []byte{1}
	if _, err := NewHop(k); err == nil {
		t.Fatal("short Kb")
	}
}

func pairedHops(t *testing.T, n int) (clientHops, relayHops []*Hop) {
	t.Helper()
	for i := range n {
		k := dummyKeys(byte(i + 1))
		h, err := NewHop(k)
		if err != nil {
			t.Fatal(err)
		}
		clientHops = append(clientHops, h)
		h2, err := NewHop(k)
		if err != nil {
			t.Fatal(err)
		}
		relayHops = append(relayHops, h2)
	}
	return
}

func dummyKeys(seed byte) *CircuitKeys {
	fill := func(n int) []byte {
		b := make([]byte, n)
		for i := range b {
			b[i] = seed + byte(i)
		}
		return b
	}
	return &CircuitKeys{Df: fill(20), Db: fill(20), Kf: fill(16), Kb: fill(16), KH: fill(20)}
}

type dumbHash struct{}

func (dumbHash) Write(p []byte) (int, error) { return len(p), nil }
func (dumbHash) Sum(b []byte) []byte         { return b }
func (dumbHash) Reset()                      {}
func (dumbHash) Size() int                   { return 20 }
func (dumbHash) BlockSize() int              { return 64 }

func TestCloneHashNotMarshaler(t *testing.T) {
	var _ hash.Hash = dumbHash{}
	if cloneHash(dumbHash{}) != nil {
		t.Fatal("expected nil")
	}
}

type failMarshal struct{ dumbHash }

func (failMarshal) MarshalBinary() ([]byte, error) { return nil, errClone }

type badMarshal struct{ dumbHash }

func (badMarshal) MarshalBinary() ([]byte, error) { return []byte("not-a-sha1-state"), nil }

var errClone = errString("no")

type errString string

func (e errString) Error() string { return string(e) }

func TestCloneHashMarshalError(t *testing.T) {
	if cloneHash(failMarshal{}) != nil {
		t.Fatal("marshal")
	}
	if cloneHash(badMarshal{}) != nil {
		t.Fatal("unmarshal")
	}
}

func TestRecognizeFailsWhenDigestCannotClone(t *testing.T) {
	h, err := NewHop(dummyKeys(1))
	if err != nil {
		t.Fatal(err)
	}
	body := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte("x")})
	h.fDigest = dumbHash{}
	if h.RecognizeForward(body) {
		t.Fatal("forward")
	}
	h.bDigest = dumbHash{}
	if h.RecognizeBackward(body) {
		t.Fatal("backward")
	}
}
