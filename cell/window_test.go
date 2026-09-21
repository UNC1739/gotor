package cell

import "testing"

func TestNeedSendmeCircuit(t *testing.T) {
	d := CircWindowStart
	sends := 0
	for i := 0; i < CircWindowStart; i++ {
		d--
		if NeedSendme(d, CircWindowStart, CircWindowInc) {
			sends++
			d += CircWindowInc
		}
	}
	if sends != CircWindowStart/CircWindowInc {
		t.Fatalf("sends=%d", sends)
	}
	if d != CircWindowStart {
		t.Fatalf("deliver=%d", d)
	}
}

func TestNeedSendmeStream(t *testing.T) {
	d := StreamWindowStart
	sends := 0
	for i := 0; i < StreamWindowStart; i++ {
		d--
		if NeedSendme(d, StreamWindowStart, StreamWindowInc) {
			sends++
			d += StreamWindowInc
		}
	}
	if sends != StreamWindowStart/StreamWindowInc {
		t.Fatalf("sends=%d", sends)
	}
}
