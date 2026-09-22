package cell

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const (
	RelayHeaderLen = 11
	MaxRelayData   = BodyLen - RelayHeaderLen

	RelayBegin      = 1
	RelayData       = 2
	RelayEnd        = 3
	RelayConnected  = 4
	RelaySendme     = 5
	RelayExtend     = 6
	RelayExtended   = 7
	RelayTruncate   = 8
	RelayTruncated  = 9
	RelayDrop       = 10
	RelayResolve    = 11
	RelayResolved   = 12
	RelayBeginDir   = 13
	RelayExtend2    = 14
	RelayExtended2  = 15

	EndReasonDone           = 6
	EndReasonConnectRefused = 3
	EndReasonExitPolicy     = 4
	EndReasonMisc           = 1
	EndReasonNotDirectory   = 13
)

type Relay struct {
	Command  byte
	StreamID uint16
	Digest   [4]byte
	Data     []byte
}

func EncodeRelay(r Relay) []byte {
	if len(r.Data) > MaxRelayData {
		r.Data = r.Data[:MaxRelayData]
	}
	body := make([]byte, BodyLen)
	body[0] = r.Command
	binary.BigEndian.PutUint16(body[3:5], r.StreamID)
	copy(body[5:9], r.Digest[:])
	binary.BigEndian.PutUint16(body[9:11], uint16(len(r.Data)))
	copy(body[11:], r.Data)
	if pad := BodyLen - 11 - len(r.Data); pad > 0 {
		z := 4
		if pad < z {
			z = pad
		}
		if pad > z {
			_, _ = rand.Read(body[11+len(r.Data)+z:])
		}
	}
	return body
}

func DecodeRelay(body []byte) (*Relay, error) {
	if len(body) < RelayHeaderLen {
		return nil, fmt.Errorf("short relay body")
	}
	n := int(binary.BigEndian.Uint16(body[9:11]))
	if n < 0 || 11+n > len(body) {
		return nil, fmt.Errorf("invalid relay length %d", n)
	}
	r := &Relay{
		Command:  body[0],
		StreamID: binary.BigEndian.Uint16(body[3:5]),
		Data:     append([]byte(nil), body[11:11+n]...),
	}
	copy(r.Digest[:], body[5:9])
	return r, nil
}

func RecognizedZero(body []byte) bool {
	return len(body) >= 3 && body[1] == 0 && body[2] == 0
}

func ZeroDigest(body []byte) []byte {
	out := append([]byte(nil), body...)
	if len(out) >= 9 {
		out[5], out[6], out[7], out[8] = 0, 0, 0, 0
	}
	return out
}

func SetDigest(body []byte, d []byte) {
	if len(body) >= 9 {
		copy(body[5:9], d[:4])
	}
}

func BeginPayload(host string, port uint16) []byte {
	s := fmt.Sprintf("%s:%d", host, port)
	p := make([]byte, len(s)+1+4)
	copy(p, s)
	return p
}

func ParseBegin(data []byte) (host string, port uint16, err error) {
	nul := -1
	for i, b := range data {
		if b == 0 {
			nul = i
			break
		}
	}
	if nul < 0 {
		nul = len(data)
	}
	addr := string(data[:nul])
	var h string
	var p int
	n, scanErr := fmt.Sscanf(addr, "%s", &h)
	_ = n
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			h = addr[:i]
			if _, err2 := fmt.Sscanf(addr[i+1:], "%d", &p); err2 != nil {
				return "", 0, fmt.Errorf("bad BEGIN port")
			}
			if p < 0 || p > 65535 {
				return "", 0, fmt.Errorf("bad BEGIN port")
			}
			return h, uint16(p), nil
		}
	}
	return "", 0, fmt.Errorf("bad BEGIN address %q: %v", addr, scanErr)
}

const (
	LSIPv4    = 0x00
	LSLegacyID = 0x02
	LSEd25519 = 0x03
	HTypenTor = 0x0002
)

func EncodeExtend2(ipv4 [4]byte, orport uint16, identity [20]byte, edid []byte, htype uint16, hdata []byte) []byte {
	nspec := 2
	if len(edid) == 32 {
		nspec = 3
	}
	n := 1 + (1 + 1 + 6) + (1 + 1 + 20)
	if nspec == 3 {
		n += 1 + 1 + 32
	}
	n += 2 + 2 + len(hdata)
	buf := make([]byte, n)
	off := 0
	buf[off] = byte(nspec)
	off++
	buf[off] = LSIPv4
	off++
	buf[off] = 6
	off++
	copy(buf[off:], ipv4[:])
	off += 4
	binary.BigEndian.PutUint16(buf[off:], orport)
	off += 2
	buf[off] = LSLegacyID
	off++
	buf[off] = 20
	off++
	copy(buf[off:], identity[:])
	off += 20
	if nspec == 3 {
		buf[off] = LSEd25519
		off++
		buf[off] = 32
		off++
		copy(buf[off:], edid)
		off += 32
	}
	binary.BigEndian.PutUint16(buf[off:], htype)
	off += 2
	binary.BigEndian.PutUint16(buf[off:], uint16(len(hdata)))
	off += 2
	copy(buf[off:], hdata)
	return buf
}

type LinkSpec struct {
	Type byte
	Data []byte
}

type Extend2 struct {
	Specs []LinkSpec
	HType uint16
	HData []byte
}

func ParseExtend2(data []byte) (*Extend2, error) {
	if len(data) < 1 {
		return nil, fmt.Errorf("short EXTEND2")
	}
	nspec := int(data[0])
	off := 1
	e := &Extend2{}
	for i := 0; i < nspec; i++ {
		if off+2 > len(data) {
			return nil, fmt.Errorf("short EXTEND2 spec")
		}
		t := data[off]
		l := int(data[off+1])
		off += 2
		if off+l > len(data) {
			return nil, fmt.Errorf("short EXTEND2 spec data")
		}
		e.Specs = append(e.Specs, LinkSpec{Type: t, Data: append([]byte(nil), data[off : off+l]...)})
		off += l
	}
	if off+4 > len(data) {
		return nil, fmt.Errorf("short EXTEND2 handshake")
	}
	e.HType = binary.BigEndian.Uint16(data[off:])
	off += 2
	n := int(binary.BigEndian.Uint16(data[off:]))
	off += 2
	if off+n > len(data) {
		return nil, fmt.Errorf("short EXTEND2 hdata")
	}
	e.HData = append([]byte(nil), data[off:off+n]...)
	return e, nil
}

func (e *Extend2) IPv4Port() ([4]byte, uint16, bool) {
	var ip [4]byte
	for _, s := range e.Specs {
		if s.Type == LSIPv4 && len(s.Data) == 6 {
			copy(ip[:], s.Data[:4])
			return ip, binary.BigEndian.Uint16(s.Data[4:6]), true
		}
	}
	return ip, 0, false
}

func (e *Extend2) LegacyID() ([20]byte, bool) {
	var id [20]byte
	for _, s := range e.Specs {
		if s.Type == LSLegacyID && len(s.Data) == 20 {
			copy(id[:], s.Data)
			return id, true
		}
	}
	return id, false
}

func EncodeExtended2(hdata []byte) []byte {
	buf := make([]byte, 2+len(hdata))
	binary.BigEndian.PutUint16(buf, uint16(len(hdata)))
	copy(buf[2:], hdata)
	return buf
}

func ParseExtended2(data []byte) ([]byte, error) {
	return ParseCreated2(data)
}

const (
	ResolvedHostname      = 0x00
	ResolvedIPv4          = 0x04
	ResolvedIPv6          = 0x06
	ResolvedErrTransient  = 0xf0
	ResolvedErr           = 0xf1
)

type Resolved struct {
	Type  byte
	Value []byte
	TTL   uint32
}

func EncodeResolve(host string) []byte {
	return append([]byte(host), 0)
}

func ParseResolve(data []byte) string {
	for i, b := range data {
		if b == 0 {
			return string(data[:i])
		}
	}
	return string(data)
}

func EncodeResolved(answers []Resolved) []byte {
	var buf []byte
	for _, a := range answers {
		buf = append(buf, a.Type, byte(len(a.Value)))
		buf = append(buf, a.Value...)
		var ttl [4]byte
		binary.BigEndian.PutUint32(ttl[:], a.TTL)
		buf = append(buf, ttl[:]...)
	}
	return buf
}

func ParseResolved(data []byte) ([]Resolved, error) {
	var out []Resolved
	off := 0
	for off < len(data) {
		if off+2 > len(data) {
			return nil, fmt.Errorf("short RESOLVED")
		}
		t := data[off]
		n := int(data[off+1])
		off += 2
		if off+n+4 > len(data) {
			return nil, fmt.Errorf("short RESOLVED value")
		}
		val := append([]byte(nil), data[off:off+n]...)
		off += n
		ttl := binary.BigEndian.Uint32(data[off : off+4])
		off += 4
		out = append(out, Resolved{Type: t, Value: val, TTL: ttl})
	}
	return out, nil
}
