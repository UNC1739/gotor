package directory

import (
	"bufio"
	"crypto/sha256"
	"strings"
)

func ParseMicrodescriptors(doc string, relays []*Relay) error {
	byHash := map[string]*Relay{}
	for _, r := range relays {
		if len(r.MicroHash) == 32 {
			byHash[string(r.MicroHash)] = r
		}
	}
	for _, part := range splitMicros(doc) {
		sum := sha256.Sum256([]byte(part))
		r := byHash[string(sum[:])]
		if r == nil {
			continue
		}
		applyMicro(r, part)
	}
	return nil
}

func splitMicros(doc string) []string {
	const start = "onion-key\n"
	var out []string
	for {
		i := strings.Index(doc, start)
		if i < 0 {
			break
		}
		doc = doc[i:]
		j := strings.Index(doc[len(start):], start)
		if j < 0 {
			out = append(out, doc)
			break
		}
		cut := len(start) + j
		out = append(out, doc[:cut])
		doc = doc[cut:]
	}
	return out
}

func applyMicro(r *Relay, doc string) {
	sc := bufio.NewScanner(strings.NewReader(doc))
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "ntor-onion-key":
			if len(fields) < 2 {
				continue
			}
			raw, err := b64(fields[1], 32)
			if err != nil {
				continue
			}
			copy(r.NTorOnionKey[:], raw)
		case "id":
			if len(fields) < 3 || fields[1] != "ed25519" {
				continue
			}
			raw, err := b64(fields[2], 32)
			if err != nil {
				continue
			}
			r.Ed25519ID = raw
		case "p":
			if len(fields) >= 2 && fields[1] == "accept" {
				r.ExitAccept = true
			}
		}
	}
}
