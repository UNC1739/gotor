package cell

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

const (
	RelayHeaderLen = 11
	MaxRelayData   = BodyLen - RelayHeaderLen

	RelayBegin     = 1
	RelayData      = 2
	RelayEnd       = 3
	RelayConnected = 4
	RelaySendme    = 5
	RelayExtend    = 6
	RelayExtended  = 7
	RelayTruncate  = 8
	RelayTruncated = 9
	RelayDrop      = 10
	RelayResolve   = 11
	RelayResolved  = 12
	RelayBeginDir  = 13
	RelayExtend2   = 14
	RelayExtended2 = 15

	RelayEstablishIntro        = 32
	RelayEstablishRendezvous   = 33
	RelayIntroduce1            = 34
	RelayIntroduce2            = 35
	RelayRendezvous1           = 36
	RelayRendezvous2           = 37
	RelayIntroEstablished      = 38
	RelayRendezvousEstablished = 39
	RelayIntroduceAck          = 40
	RelayPaddingNegotiate      = 41
	RelayPaddingNegotiated     = 42
	RelayXoff                  = 43
	RelayXon                   = 44

	CircPadCommandStop      = 1
	CircPadCommandStart     = 2
	CircPadResponseOK       = 1
	CircPadResponseERR      = 2
	CircPadMachineCircSetup = 1
	EndReasonDone           = 6
	EndReasonConnectRefused = 3
	EndReasonExitPolicy     = 4
	EndReasonMisc           = 1
	EndReasonResolveFailed  = 2
	EndReasonNotDirectory   = 13

	BeginIPv6OK        uint32 = 1 << 0
	BeginIPv4NotOK     uint32 = 1 << 1
	BeginIPv6Preferred uint32 = 1 << 2
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

const SendmeV1 = 1

func EncodeSendmeV1(digest []byte) []byte {
	if len(digest) > 20 {
		digest = digest[:20]
	}
	buf := make([]byte, 3+20)
	buf[0] = SendmeV1
	binary.BigEndian.PutUint16(buf[1:3], 20)
	copy(buf[3:], digest)
	return buf
}

func ParseSendme(data []byte) (ver byte, digest []byte, err error) {
	if len(data) == 0 {
		return 0, nil, nil
	}
	if len(data) < 3 {
		return 0, nil, fmt.Errorf("short SENDME")
	}
	ver = data[0]
	n := int(binary.BigEndian.Uint16(data[1:3]))
	if len(data) < 3+n {
		return 0, nil, fmt.Errorf("short SENDME data")
	}
	if ver == SendmeV1 {
		if n < 20 {
			return ver, nil, fmt.Errorf("short SENDME digest")
		}
		return ver, data[3 : 3+20], nil
	}
	return ver, nil, nil
}

func BeginPayload(host string, port uint16) []byte {
	return BeginPayloadFlags(host, port, 0)
}

func BeginPayloadFlags(host string, port uint16, flags uint32) []byte {
	s := net.JoinHostPort(host, strconv.Itoa(int(port)))
	n := len(s) + 1
	if flags != 0 {
		n += 4
	}
	p := make([]byte, n)
	copy(p, s)
	if flags != 0 {
		binary.BigEndian.PutUint32(p[len(s)+1:], flags)
	}
	return p
}

func ParseBegin(data []byte) (host string, port uint16, flags uint32, err error) {
	nul := -1
	for i, b := range data {
		if b == 0 {
			nul = i
			break
		}
	}
	if nul < 0 {
		nul = len(data)
	} else if nul+1+4 <= len(data) {
		flags = binary.BigEndian.Uint32(data[nul+1 : nul+5])
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
				return "", 0, 0, fmt.Errorf("bad BEGIN port")
			}
			if p < 0 || p > 65535 {
				return "", 0, 0, fmt.Errorf("bad BEGIN port")
			}
			return h, uint16(p), flags, nil
		}
	}
	return "", 0, 0, fmt.Errorf("bad BEGIN address %q: %v", addr, scanErr)
}

func SelectBeginAddr(addrs []net.IP, flags uint32) net.IP {
	var v4, v6 []net.IP
	for _, a := range addrs {
		if a == nil {
			continue
		}
		if ip4 := a.To4(); ip4 != nil {
			v4 = append(v4, ip4)
			continue
		}
		if ip6 := a.To16(); ip6 != nil {
			v6 = append(v6, ip6)
		}
	}
	if flags&BeginIPv4NotOK != 0 {
		v4 = nil
	}
	if flags&BeginIPv6OK == 0 {
		v6 = nil
	}
	if flags&BeginIPv6Preferred != 0 && len(v6) > 0 {
		return v6[0]
	}
	if len(v4) > 0 {
		return v4[0]
	}
	if len(v6) > 0 {
		return v6[0]
	}
	return nil
}

const (
	LSIPv4     = 0x00
	LSLegacyID = 0x02
	LSEd25519  = 0x03
	HTypenTor  = 0x0002
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
		e.Specs = append(e.Specs, LinkSpec{Type: t, Data: append([]byte(nil), data[off:off+l]...)})
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

type PaddingNegotiate struct {
	Version     byte
	Command     byte
	MachineType byte
	MachineCtr  uint32
}

type PaddingNegotiated struct {
	Version     byte
	Command     byte
	Response    byte
	MachineType byte
	MachineCtr  uint32
}

func EncodePaddingNegotiate(cmd, machineType byte, ctr uint32) []byte {
	b := make([]byte, 8)
	b[1] = cmd
	b[2] = machineType
	binary.BigEndian.PutUint32(b[4:], ctr)
	return b
}

func ParsePaddingNegotiate(data []byte) (*PaddingNegotiate, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("short PADDING_NEGOTIATE")
	}
	return &PaddingNegotiate{
		Version:     data[0],
		Command:     data[1],
		MachineType: data[2],
		MachineCtr:  binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

func EncodePaddingNegotiated(cmd, response, machineType byte, ctr uint32) []byte {
	b := make([]byte, 8)
	b[1] = cmd
	b[2] = response
	b[3] = machineType
	binary.BigEndian.PutUint32(b[4:], ctr)
	return b
}

func ParsePaddingNegotiated(data []byte) (*PaddingNegotiated, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("short PADDING_NEGOTIATED")
	}
	return &PaddingNegotiated{
		Version:     data[0],
		Command:     data[1],
		Response:    data[2],
		MachineType: data[3],
		MachineCtr:  binary.BigEndian.Uint32(data[4:8]),
	}, nil
}

func EncodeXoff() []byte {
	return []byte{0}
}

func ParseXoff(data []byte) error {
	if len(data) < 1 || data[0] != 0 {
		return fmt.Errorf("bad XOFF")
	}
	return nil
}

func EncodeXon(kbps uint32) []byte {
	b := make([]byte, 5)
	binary.BigEndian.PutUint32(b[1:], kbps)
	return b
}

func ParseXon(data []byte) (uint32, error) {
	if len(data) < 5 || data[0] != 0 {
		return 0, fmt.Errorf("bad XON")
	}
	return binary.BigEndian.Uint32(data[1:5]), nil
}

const (
	ResolvedHostname     = 0x00
	ResolvedIPv4         = 0x04
	ResolvedIPv6         = 0x06
	ResolvedErrTransient = 0xf0
	ResolvedErr          = 0xf1
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
