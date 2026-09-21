package crypto

import (
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"io"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"
)

const (
	IDLen     = 20
	GLen      = 32
	HLen      = 32
	SHA1Len   = 20
	AESKeyLen = 16
	NtorHLen  = 84
	NtorRLen  = 64
	HTypeNtor = 0x0002

	protoID = "ntor-curve25519-sha256-1"
	tMac    = protoID + ":mac"
	tKey    = protoID + ":key_extract"
	tVerify = protoID + ":verify"
	mExpand = protoID + ":key_expand"
)

var (
	ErrNtorAuth     = errors.New("ntor: AUTH mismatch")
	ErrNtorInfinity = errors.New("ntor: degenerate shared secret")
	ErrNtorID       = errors.New("ntor: NODEID mismatch")
	ErrNtorKey      = errors.New("ntor: KEYID mismatch")
)

type KeyPair struct {
	Private [32]byte
	Public  [32]byte
}

func GenerateKeyPair(rand io.Reader) (*KeyPair, error) {
	kp := &KeyPair{}
	if _, err := io.ReadFull(rand, kp.Private[:]); err != nil {
		return nil, err
	}
	pub, err := curve25519.X25519(kp.Private[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	copy(kp.Public[:], pub)
	return kp, nil
}

func exp(priv, pub []byte) ([]byte, error) {
	out, err := curve25519.X25519(priv, pub)
	if err != nil {
		return nil, err
	}
	if isZero(out) {
		return nil, ErrNtorInfinity
	}
	return out, nil
}

func isZero(b []byte) bool {
	var a byte
	for _, v := range b {
		a |= v
	}
	return a == 0
}

func hmacSHA256(key string, msg []byte) []byte {
	m := hmac.New(sha256.New, []byte(key))
	m.Write(msg)
	return m.Sum(nil)
}

type CircuitKeys struct {
	Df, Db []byte
	Kf, Kb []byte
	KH     []byte
}

func expandKeys(keySeed []byte) (*CircuitKeys, error) {
	r := hkdf.Expand(sha256.New, keySeed, []byte(mExpand))
	out := make([]byte, SHA1Len+SHA1Len+AESKeyLen+AESKeyLen+SHA1Len)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return &CircuitKeys{
		Df: out[0:20],
		Db: out[20:40],
		Kf: out[40:56],
		Kb: out[56:72],
		KH: out[72:92],
	}, nil
}

func ntorSecrets(xy, xb, id, B, X, Y []byte) (keySeed, auth []byte, err error) {
	secret := make([]byte, 0, 32+32+IDLen+GLen+GLen+GLen+len(protoID))
	secret = append(secret, xy...)
	secret = append(secret, xb...)
	secret = append(secret, id...)
	secret = append(secret, B...)
	secret = append(secret, X...)
	secret = append(secret, Y...)
	secret = append(secret, protoID...)
	keySeed = hmacSHA256(tKey, secret)
	verify := hmacSHA256(tVerify, secret)
	authIn := make([]byte, 0, len(verify)+IDLen+GLen+GLen+GLen+len(protoID)+6)
	authIn = append(authIn, verify...)
	authIn = append(authIn, id...)
	authIn = append(authIn, B...)
	authIn = append(authIn, Y...)
	authIn = append(authIn, X...)
	authIn = append(authIn, protoID...)
	authIn = append(authIn, "Server"...)
	auth = hmacSHA256(tMac, authIn)
	return keySeed, auth, nil
}

type NtorClientState struct {
	X    *KeyPair
	ID   [20]byte
	B    [32]byte
	Xpub []byte
}

func NtorClientHandshake(rand io.Reader, nodeID [20]byte, ntorPub [32]byte) ([]byte, *NtorClientState, error) {
	x, err := GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	hs := make([]byte, NtorHLen)
	copy(hs[0:20], nodeID[:])
	copy(hs[20:52], ntorPub[:])
	copy(hs[52:84], x.Public[:])
	st := &NtorClientState{X: x, ID: nodeID, B: ntorPub, Xpub: x.Public[:]}
	return hs, st, nil
}

func (st *NtorClientState) Finish(reply []byte) (*CircuitKeys, error) {
	if len(reply) < NtorRLen {
		return nil, errors.New("ntor: short server reply")
	}
	Y := reply[:32]
	AUTH := reply[32:64]
	xy, err := exp(st.X.Private[:], Y)
	if err != nil {
		return nil, err
	}
	xb, err := exp(st.X.Private[:], st.B[:])
	if err != nil {
		return nil, err
	}
	keySeed, auth, err := ntorSecrets(xy, xb, st.ID[:], st.B[:], st.Xpub, Y)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(auth, AUTH) {
		return nil, ErrNtorAuth
	}
	return expandKeys(keySeed)
}

type NtorServer struct {
	ID   [20]byte
	Key  *KeyPair
}

func (s *NtorServer) Reply(rand io.Reader, handshake []byte) (reply []byte, keys *CircuitKeys, err error) {
	if len(handshake) < NtorHLen {
		return nil, nil, errors.New("ntor: short client handshake")
	}
	var id [20]byte
	copy(id[:], handshake[0:20])
	if id != s.ID {
		return nil, nil, ErrNtorID
	}
	if !hmac.Equal(handshake[20:52], s.Key.Public[:]) {
		return nil, nil, ErrNtorKey
	}
	X := handshake[52:84]
	y, err := GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	xy, err := exp(y.Private[:], X)
	if err != nil {
		return nil, nil, err
	}
	xb, err := exp(s.Key.Private[:], X)
	if err != nil {
		return nil, nil, err
	}
	keySeed, auth, err := ntorSecrets(xy, xb, s.ID[:], s.Key.Public[:], X, y.Public[:])
	if err != nil {
		return nil, nil, err
	}
	keys, err = expandKeys(keySeed)
	if err != nil {
		return nil, nil, err
	}
	reply = make([]byte, NtorRLen)
	copy(reply[0:32], y.Public[:])
	copy(reply[32:64], auth)
	return reply, keys, nil
}
