package cell

import (
	"encoding/binary"
	"fmt"
)

const confluxLinkLen = 1 + 32 + 8 + 8 + 1

type ConfluxLink struct {
	Version  byte
	Nonce    [32]byte
	LastSent uint64
	LastRecv uint64
	UX       byte
}

func EncodeConfluxLink(l ConfluxLink) []byte {
	if l.Version == 0 {
		l.Version = ConfluxVersion1
	}
	b := make([]byte, confluxLinkLen)
	b[0] = l.Version
	copy(b[1:33], l.Nonce[:])
	binary.BigEndian.PutUint64(b[33:41], l.LastSent)
	binary.BigEndian.PutUint64(b[41:49], l.LastRecv)
	b[49] = l.UX
	return b
}

func ParseConfluxLink(data []byte) (ConfluxLink, error) {
	var l ConfluxLink
	if len(data) < confluxLinkLen {
		return l, fmt.Errorf("short CONFLUX_LINK")
	}
	l.Version = data[0]
	if l.Version != ConfluxVersion1 {
		return l, fmt.Errorf("conflux version %d", l.Version)
	}
	copy(l.Nonce[:], data[1:33])
	l.LastSent = binary.BigEndian.Uint64(data[33:41])
	l.LastRecv = binary.BigEndian.Uint64(data[41:49])
	l.UX = data[49]
	return l, nil
}

func EncodeConfluxSwitch(seq uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, seq)
	return b
}

func ParseConfluxSwitch(data []byte) (uint32, error) {
	if len(data) < 4 {
		return 0, fmt.Errorf("short CONFLUX_SWITCH")
	}
	return binary.BigEndian.Uint32(data[:4]), nil
}
