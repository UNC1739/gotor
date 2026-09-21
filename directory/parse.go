package directory

import (
	"bufio"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Relay struct {
	Nickname     string
	Identity     [20]byte
	Address      net.IP
	ORPort       uint16
	DirPort      uint16
	Flags        map[string]bool
	NTorOnionKey [32]byte
	Ed25519ID    []byte
	ExitAccept   bool
}

func (r *Relay) Has(flag string) bool {
	return r.Flags[flag]
}

func ParseConsensus(doc string) ([]*Relay, error) {
	var relays []*Relay
	var cur *Relay
	sc := bufio.NewScanner(strings.NewReader(doc))
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "directory-") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "r":
			if len(fields) < 9 {
				return nil, fmt.Errorf("short r line")
			}
			ident, err := b64(fields[2], 20)
			if err != nil {
				return nil, fmt.Errorf("identity: %w", err)
			}
			ip := net.ParseIP(fields[6])
			orport, _ := strconv.Atoi(fields[7])
			dirport, _ := strconv.Atoi(fields[8])
			cur = &Relay{
				Nickname: fields[1],
				Address:  ip,
				ORPort:   uint16(orport),
				DirPort:  uint16(dirport),
				Flags:    map[string]bool{},
			}
			copy(cur.Identity[:], ident)
			relays = append(relays, cur)
		case "s":
			if cur == nil {
				continue
			}
			for _, f := range fields[1:] {
				cur.Flags[f] = true
			}
		case "p":
			if cur == nil {
				continue
			}
			if len(fields) >= 2 && fields[1] == "accept" {
				cur.ExitAccept = true
			}
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return relays, nil
}

func ParseDescriptors(doc string, relays []*Relay) error {
	byFP := map[string]*Relay{}
	for _, r := range relays {
		byFP[strings.ToUpper(hex.EncodeToString(r.Identity[:]))] = r
	}
	var cur *Relay
	sc := bufio.NewScanner(strings.NewReader(doc))
	for sc.Scan() {
		line := sc.Text()
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "router":
			cur = nil
			if len(fields) >= 2 {
				for _, r := range relays {
					if r.Nickname == fields[1] {
						cur = r
						break
					}
				}
			}
		case "fingerprint":
			fp := strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(line, "fingerprint "), " ", ""))
			if r, ok := byFP[fp]; ok {
				cur = r
			}
		case "ntor-onion-key":
			if cur == nil || len(fields) < 2 {
				continue
			}
			raw, err := b64(fields[1], 32)
			if err != nil {
				return err
			}
			copy(cur.NTorOnionKey[:], raw)
		case "master-key-ed25519":
			if cur == nil || len(fields) < 2 {
				continue
			}
			raw, err := b64(fields[1], 32)
			if err != nil {
				continue
			}
			cur.Ed25519ID = raw
		case "accept":
			if cur != nil {
				cur.ExitAccept = true
			}
		}
	}
	return sc.Err()
}

func b64(s string, want int) ([]byte, error) {
	pad := (4 - len(s)%4) % 4
	raw, err := base64.StdEncoding.DecodeString(s + strings.Repeat("=", pad))
	if err != nil {
		raw, err = base64.RawStdEncoding.DecodeString(s)
		if err != nil {
			return nil, err
		}
	}
	if want > 0 && len(raw) != want {
		return nil, fmt.Errorf("got %d bytes, want %d", len(raw), want)
	}
	return raw, nil
}

func B64(b []byte) string {
	return strings.TrimRight(base64.StdEncoding.EncodeToString(b), "=")
}

func FingerprintHex(id [20]byte) string {
	h := strings.ToUpper(hex.EncodeToString(id[:]))
	var parts []string
	for i := 0; i < len(h); i += 4 {
		end := i + 4
		if end > len(h) {
			end = len(h)
		}
		parts = append(parts, h[i:end])
	}
	return strings.Join(parts, " ")
}

func FingerprintCompact(id [20]byte) string {
	return strings.ToUpper(hex.EncodeToString(id[:]))
}
