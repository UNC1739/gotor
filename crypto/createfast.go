package crypto

import (
	"crypto/hmac"
	"crypto/sha1"
	"errors"
	"io"
)

func KDFTor(k0 []byte, n int) []byte {
	var out []byte
	for i := 0; len(out) < n; i++ {
		h := sha1.New()
		h.Write(k0)
		h.Write([]byte{byte(i)})
		out = append(out, h.Sum(nil)...)
	}
	return out[:n]
}

func keysFromTOR(k0 []byte) *CircuitKeys {
	out := KDFTor(k0, SHA1Len+SHA1Len+SHA1Len+AESKeyLen+AESKeyLen)
	return &CircuitKeys{
		KH: out[0:20],
		Df: out[20:40],
		Db: out[40:60],
		Kf: out[60:76],
		Kb: out[76:92],
	}
}

func CreateFastHandshake(r io.Reader) (x []byte, err error) {
	x = make([]byte, SHA1Len)
	if _, err := io.ReadFull(r, x); err != nil {
		return nil, err
	}
	return x, nil
}

func CreateFastReply(r io.Reader, x []byte) (y, kh []byte, keys *CircuitKeys, err error) {
	if len(x) != SHA1Len {
		return nil, nil, nil, errors.New("CREATE_FAST: bad X")
	}
	y = make([]byte, SHA1Len)
	if _, err := io.ReadFull(r, y); err != nil {
		return nil, nil, nil, err
	}
	k0 := append(append([]byte{}, x...), y...)
	keys = keysFromTOR(k0)
	return y, keys.KH, keys, nil
}

func CreateFastFinish(x, y, kh []byte) (*CircuitKeys, error) {
	if len(x) != SHA1Len || len(y) != SHA1Len || len(kh) != SHA1Len {
		return nil, errors.New("CREATED_FAST: bad length")
	}
	k0 := append(append([]byte{}, x...), y...)
	keys := keysFromTOR(k0)
	if !hmac.Equal(keys.KH, kh) {
		return nil, errors.New("CREATED_FAST: KH mismatch")
	}
	return keys, nil
}
