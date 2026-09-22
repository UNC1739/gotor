package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha1"
	"encoding"
	"hash"

	"github.com/adam/gotor/cell"
)

type Hop struct {
	fDigest hash.Hash
	bDigest hash.Hash
	fStream cipher.Stream
	bStream cipher.Stream
}

func NewHop(k *CircuitKeys) (*Hop, error) {
	fb, err := aes.NewCipher(k.Kf)
	if err != nil {
		return nil, err
	}
	bb, err := aes.NewCipher(k.Kb)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	fd := sha1.New()
	fd.Write(k.Df)
	bd := sha1.New()
	bd.Write(k.Db)
	return &Hop{
		fDigest: fd,
		bDigest: bd,
		fStream: cipher.NewCTR(fb, iv),
		bStream: cipher.NewCTR(bb, append([]byte(nil), iv...)),
	}, nil
}

func cloneHash(h hash.Hash) hash.Hash {
	m, ok := h.(encoding.BinaryMarshaler)
	if !ok {
		return nil
	}
	b, err := m.MarshalBinary()
	if err != nil {
		return nil
	}
	c := sha1.New()
	if err := c.(encoding.BinaryUnmarshaler).UnmarshalBinary(b); err != nil {
		return nil
	}
	return c
}

func updateDigest(h hash.Hash, body []byte) []byte {
	h.Write(cell.ZeroDigest(body))
	sum := h.Sum(nil)
	return sum[:4]
}

func (h *Hop) EncryptForward(body []byte) {
	h.fStream.XORKeyStream(body, body)
}

func (h *Hop) DecryptForward(body []byte) {
	h.fStream.XORKeyStream(body, body)
}

func (h *Hop) EncryptBackward(body []byte) {
	h.bStream.XORKeyStream(body, body)
}

func (h *Hop) DecryptBackward(body []byte) {
	h.bStream.XORKeyStream(body, body)
}

func (h *Hop) SealForward(body []byte) {
	d := updateDigest(h.fDigest, body)
	cell.SetDigest(body, d)
	h.EncryptForward(body)
}

func (h *Hop) RecognizeForward(body []byte) bool {
	if !cell.RecognizedZero(body) {
		return false
	}
	cl := cloneHash(h.fDigest)
	if cl == nil {
		return false
	}
	d := updateDigest(cl, body)
	if d[0] != body[5] || d[1] != body[6] || d[2] != body[7] || d[3] != body[8] {
		return false
	}
	h.fDigest.Write(cell.ZeroDigest(body))
	return true
}

func (h *Hop) SealBackward(body []byte) {
	d := updateDigest(h.bDigest, body)
	cell.SetDigest(body, d)
	h.EncryptBackward(body)
}

func (h *Hop) RecognizeBackward(body []byte) bool {
	if !cell.RecognizedZero(body) {
		return false
	}
	cl := cloneHash(h.bDigest)
	if cl == nil {
		return false
	}
	d := updateDigest(cl, body)
	if d[0] != body[5] || d[1] != body[6] || d[2] != body[7] || d[3] != body[8] {
		return false
	}
	h.bDigest.Write(cell.ZeroDigest(body))
	return true
}

func (h *Hop) ForwardDigest() []byte {
	return h.fDigest.Sum(nil)
}

func (h *Hop) BackwardDigest() []byte {
	return h.bDigest.Sum(nil)
}

func OnionEncrypt(hops []*Hop, dest int, body []byte) {
	d := updateDigest(hops[dest].fDigest, body)
	cell.SetDigest(body, d)
	for i := dest; i >= 0; i-- {
		hops[i].EncryptForward(body)
	}
}

func OnionDecrypt(hops []*Hop, body []byte) (hop int, ok bool) {
	for i, h := range hops {
		h.DecryptBackward(body)
		if h.RecognizeBackward(body) {
			return i, true
		}
	}
	return -1, false
}
