package crypto

import (
	"bytes"
	"testing"

	"github.com/adam/gotor/cell"
)

func TestOnionLayers(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	msg := cell.EncodeRelay(cell.Relay{Command: cell.RelayBegin, StreamID: 1, Data: []byte("127.0.0.1:80")})
	OnionEncrypt(hops, 2, msg)

	body := append([]byte(nil), msg...)
	for i := 0; i < 3; i++ {
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
	for i := 0; i < 16; i++ {
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

func TestClientStopsAtOriginatingHop(t *testing.T) {
	hops, exitHops := pairedHops(t, 3)
	for dest := 0; dest < 3; dest++ {
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

func pairedHops(t *testing.T, n int) (clientHops, relayHops []*Hop) {
	t.Helper()
	for i := 0; i < n; i++ {
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
