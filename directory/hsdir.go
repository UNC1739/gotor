package directory

import (
	"bytes"
	"crypto/ed25519"
	"sort"

	"github.com/adam/gotor/crypto"
)

func ResponsibleHSDirs(hsdirs []*Relay, blinded ed25519.PublicKey, srv []byte, periodNum uint64, spread int) []*Relay {
	if spread < 1 {
		spread = crypto.HSSpreadFetch
	}
	type node struct {
		r   *Relay
		idx []byte
	}
	var ring []node
	for _, r := range hsdirs {
		if r == nil || len(r.Ed25519ID) != 32 {
			continue
		}
		ring = append(ring, node{
			r:   r,
			idx: crypto.NodeIndex(r.Ed25519ID, srv, crypto.HSPeriodLength, periodNum),
		})
	}
	if len(ring) == 0 {
		return nil
	}
	sort.Slice(ring, func(i, j int) bool {
		return bytes.Compare(ring[i].idx, ring[j].idx) < 0
	})
	seen := map[[20]byte]bool{}
	var out []*Relay
	for replica := uint64(1); replica <= crypto.HSReplicas; replica++ {
		hsIdx := crypto.HSIndex(blinded, replica, crypto.HSPeriodLength, periodNum)
		start := 0
		for start < len(ring) && bytes.Compare(ring[start].idx, hsIdx) < 0 {
			start++
		}
		if start == len(ring) {
			start = 0
		}
		added := 0
		i := start
		for added < spread {
			r := ring[i].r
			if !seen[r.Identity] {
				seen[r.Identity] = true
				out = append(out, r)
				added++
			}
			i++
			if i == len(ring) {
				i = 0
			}
			if i == start {
				break
			}
		}
	}
	return out
}
