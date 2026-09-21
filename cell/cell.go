package cell

import (
	"encoding/binary"
	"fmt"
	"io"
)

const (
	BodyLen = 509

	CmdPadding          = 0
	CmdCreate           = 1
	CmdCreated          = 2
	CmdRelay            = 3
	CmdDestroy          = 4
	CmdCreateFast       = 5
	CmdCreatedFast      = 6
	CmdVersions         = 7
	CmdNetinfo          = 8
	CmdRelayEarly       = 9
	CmdCreate2          = 10
	CmdCreated2         = 11
	CmdPaddingNegotiate = 12
	CmdVpadding         = 128
	CmdCerts            = 129
	CmdAuthChallenge    = 130
	CmdAuthenticate     = 131
)

type Cell struct {
	CircID  uint32
	Command byte
	Body    []byte
}

func IsVarLen(cmd byte) bool {
	return cmd == CmdVersions || cmd >= 128
}

func CircIDLen(linkVer int) int {
	if linkVer >= 4 {
		return 4
	}
	return 2
}

func Read(r io.Reader, circIDLen int) (*Cell, error) {
	hdr := make([]byte, circIDLen+1)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return nil, err
	}
	var circID uint32
	if circIDLen == 2 {
		circID = uint32(binary.BigEndian.Uint16(hdr[:2]))
	} else {
		circID = binary.BigEndian.Uint32(hdr[:4])
	}
	cmd := hdr[circIDLen]
	if IsVarLen(cmd) {
		var ln [2]byte
		if _, err := io.ReadFull(r, ln[:]); err != nil {
			return nil, err
		}
		n := int(binary.BigEndian.Uint16(ln[:]))
		body := make([]byte, n)
		if n > 0 {
			if _, err := io.ReadFull(r, body); err != nil {
				return nil, err
			}
		}
		return &Cell{CircID: circID, Command: cmd, Body: body}, nil
	}
	body := make([]byte, BodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return &Cell{CircID: circID, Command: cmd, Body: body}, nil
}

func (c *Cell) Write(w io.Writer, circIDLen int) error {
	hdr := make([]byte, circIDLen+1)
	if circIDLen == 2 {
		if c.CircID > 0xffff {
			return fmt.Errorf("circid %d too large for 2-byte field", c.CircID)
		}
		binary.BigEndian.PutUint16(hdr[:2], uint16(c.CircID))
	} else {
		binary.BigEndian.PutUint32(hdr[:4], c.CircID)
	}
	hdr[circIDLen] = c.Command
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if IsVarLen(c.Command) {
		var ln [2]byte
		binary.BigEndian.PutUint16(ln[:], uint16(len(c.Body)))
		if _, err := w.Write(ln[:]); err != nil {
			return err
		}
		_, err := w.Write(c.Body)
		return err
	}
	body := make([]byte, BodyLen)
	copy(body, c.Body)
	_, err := w.Write(body)
	return err
}

func Versions(circIDLen int, versions ...uint16) *Cell {
	body := make([]byte, 2*len(versions))
	for i, v := range versions {
		binary.BigEndian.PutUint16(body[i*2:], v)
	}
	_ = circIDLen
	return &Cell{Command: CmdVersions, Body: body}
}

func ParseVersions(body []byte) ([]uint16, error) {
	if len(body)%2 != 0 {
		return nil, fmt.Errorf("malformed VERSIONS body")
	}
	out := make([]uint16, len(body)/2)
	for i := range out {
		out[i] = binary.BigEndian.Uint16(body[i*2:])
	}
	return out, nil
}

func NegotiateVersion(a, b []uint16) (uint16, error) {
	best := uint16(0)
	set := map[uint16]struct{}{}
	for _, v := range a {
		set[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[v]; ok && v > best {
			best = v
		}
	}
	if best == 0 {
		return 0, fmt.Errorf("no common link protocol")
	}
	return best, nil
}

func Create2(circID uint32, htype uint16, hdata []byte) *Cell {
	body := make([]byte, 4+len(hdata))
	binary.BigEndian.PutUint16(body[0:2], htype)
	binary.BigEndian.PutUint16(body[2:4], uint16(len(hdata)))
	copy(body[4:], hdata)
	return &Cell{CircID: circID, Command: CmdCreate2, Body: body}
}

func ParseCreate2(body []byte) (htype uint16, hdata []byte, err error) {
	if len(body) < 4 {
		return 0, nil, fmt.Errorf("short CREATE2")
	}
	htype = binary.BigEndian.Uint16(body[0:2])
	n := int(binary.BigEndian.Uint16(body[2:4]))
	if len(body) < 4+n {
		return 0, nil, fmt.Errorf("short CREATE2 handshake")
	}
	return htype, body[4 : 4+n], nil
}

func Created2(circID uint32, hdata []byte) *Cell {
	body := make([]byte, 2+len(hdata))
	binary.BigEndian.PutUint16(body[0:2], uint16(len(hdata)))
	copy(body[2:], hdata)
	return &Cell{CircID: circID, Command: CmdCreated2, Body: body}
}

func ParseCreated2(body []byte) ([]byte, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("short CREATED2")
	}
	n := int(binary.BigEndian.Uint16(body[0:2]))
	if len(body) < 2+n {
		return nil, fmt.Errorf("short CREATED2 handshake")
	}
	return body[2 : 2+n], nil
}

func Destroy(circID uint32, reason byte) *Cell {
	return &Cell{CircID: circID, Command: CmdDestroy, Body: []byte{reason}}
}
