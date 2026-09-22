package crypto

import "fmt"

const (
	ExtCCRequest  = 1
	ExtCCResponse = 2
	CCSendmeInc   = 100
)

type NtorExt struct {
	Type byte
	Data []byte
}

func EncodeNtorExts(exts []NtorExt) []byte {
	b := []byte{byte(len(exts))}
	for _, e := range exts {
		b = append(b, e.Type, byte(len(e.Data)))
		b = append(b, e.Data...)
	}
	return b
}

func ParseNtorExts(b []byte) ([]NtorExt, error) {
	if len(b) == 0 {
		return nil, nil
	}
	n := int(b[0])
	off := 1
	var out []NtorExt
	for i := 0; i < n; i++ {
		if off+2 > len(b) {
			return nil, fmt.Errorf("short ntor extension")
		}
		t := b[off]
		l := int(b[off+1])
		off += 2
		if off+l > len(b) {
			return nil, fmt.Errorf("short ntor extension body")
		}
		out = append(out, NtorExt{Type: t, Data: append([]byte(nil), b[off:off+l]...)})
		off += l
	}
	return out, nil
}

func EncodeCCRequest() []byte {
	return EncodeNtorExts([]NtorExt{{Type: ExtCCRequest}})
}

func EncodeCCResponse(inc byte) []byte {
	return EncodeNtorExts([]NtorExt{{Type: ExtCCResponse, Data: []byte{inc}}})
}

func HasCCRequest(b []byte) bool {
	exts, err := ParseNtorExts(b)
	if err != nil {
		return false
	}
	for _, e := range exts {
		if e.Type == ExtCCRequest {
			return true
		}
	}
	return false
}

func CCSendmeIncFrom(b []byte) (byte, bool) {
	exts, err := ParseNtorExts(b)
	if err != nil {
		return 0, false
	}
	for _, e := range exts {
		if e.Type == ExtCCResponse && len(e.Data) >= 1 {
			return e.Data[0], true
		}
	}
	return 0, false
}

func CCResponseIfRequested(clientExtra []byte) []byte {
	if HasCCRequest(clientExtra) {
		return EncodeCCResponse(CCSendmeInc)
	}
	return nil
}
