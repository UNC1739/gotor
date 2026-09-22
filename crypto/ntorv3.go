package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/sha3"
)

const (
	EdIDLen      = 32
	NtorV3MACLen = 32
	NtorV3EncLen = 32
	NtorV3MinH   = EdIDLen + GLen + GLen + NtorV3MACLen
	NtorV3MinR   = GLen + NtorV3MACLen

	protoIDv3 = "ntor3-curve25519-sha3_256-1"
	tMsgKDF   = protoIDv3 + ":kdf_phase1"
	tMsgMAC   = protoIDv3 + ":msg_mac"
	tKeySeed3 = protoIDv3 + ":key_seed"
	tVerify3  = protoIDv3 + ":verify"
	tFinal    = protoIDv3 + ":kdf_final"
	tAuth     = protoIDv3 + ":auth_final"

	NtorV3CircuitVerify = "circuit extend"
)

var (
	ErrNtorV3MAC = errors.New("ntor-v3: MAC mismatch")
	ErrNtorV3Len = errors.New("ntor-v3: short handshake")
)

func encap(s []byte) []byte {
	out := make([]byte, 8+len(s))
	binary.BigEndian.PutUint64(out[:8], uint64(len(s)))
	copy(out[8:], s)
	return out
}

func h3(t string, s []byte) []byte {
	d := sha3.New256()
	d.Write(encap([]byte(t)))
	d.Write(s)
	return d.Sum(nil)
}

func mac3(t string, k, msg []byte) []byte {
	d := sha3.New256()
	d.Write(encap([]byte(t)))
	d.Write(encap(k))
	d.Write(msg)
	return d.Sum(nil)
}

func kdf3(t string, s []byte, n int) []byte {
	d := sha3.NewShake256()
	d.Write(encap([]byte(t)))
	d.Write(s)
	out := make([]byte, n)
	d.Read(out)
	return out
}

func aes256CTR(key, m []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), m...)
	cipher.NewCTR(block, make([]byte, aes.BlockSize)).XORKeyStream(out, out)
	return out, nil
}

func keysFromStream(ks []byte) *CircuitKeys {
	return &CircuitKeys{
		Df: ks[0:20],
		Db: ks[20:40],
		Kf: ks[40:56],
		Kb: ks[56:72],
		KH: ks[72:92],
	}
}

func ntorV3Phase1(bx, id, X, B, ver []byte) (encK, macK []byte) {
	secret := make([]byte, 0, len(bx)+len(id)+len(X)+len(B)+len(protoIDv3)+8+len(ver))
	secret = append(secret, bx...)
	secret = append(secret, id...)
	secret = append(secret, X...)
	secret = append(secret, B...)
	secret = append(secret, protoIDv3...)
	secret = append(secret, encap(ver)...)
	keys := kdf3(tMsgKDF, secret, NtorV3EncLen+NtorV3MACLen)
	return keys[:NtorV3EncLen], keys[NtorV3EncLen:]
}

func ntorV3Secret(xy, xb, id, B, X, Y, ver []byte) (keySeed, verify []byte) {
	secret := make([]byte, 0, len(xy)+len(xb)+len(id)+len(B)+len(X)+len(Y)+len(protoIDv3)+8+len(ver))
	secret = append(secret, xy...)
	secret = append(secret, xb...)
	secret = append(secret, id...)
	secret = append(secret, B...)
	secret = append(secret, X...)
	secret = append(secret, Y...)
	secret = append(secret, protoIDv3...)
	secret = append(secret, encap(ver)...)
	return h3(tKeySeed3, secret), h3(tVerify3, secret)
}

func ntorV3Auth(verify, id, B, Y, X, msgMAC, encSM []byte) []byte {
	in := make([]byte, 0, len(verify)+len(id)+len(B)+len(Y)+len(X)+len(msgMAC)+8+len(encSM)+len(protoIDv3)+6)
	in = append(in, verify...)
	in = append(in, id...)
	in = append(in, B...)
	in = append(in, Y...)
	in = append(in, X...)
	in = append(in, msgMAC...)
	in = append(in, encap(encSM)...)
	in = append(in, protoIDv3...)
	in = append(in, "Server"...)
	return h3(tAuth, in)
}

func ntorV3Expand(keySeed []byte, extraLen int) (encKey, keystream []byte) {
	raw := kdf3(tFinal, keySeed, NtorV3EncLen+extraLen)
	return raw[:NtorV3EncLen], raw[NtorV3EncLen:]
}

type NtorV3ClientState struct {
	X      *KeyPair
	ID     [32]byte
	B      [32]byte
	Xpub   []byte
	Bx     []byte
	MsgMAC []byte
	VER    []byte
}

func NtorV3ClientHandshake(rand io.Reader, nodeID [32]byte, ntorPub [32]byte, extra, ver []byte) ([]byte, *NtorV3ClientState, error) {
	x, err := GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, err
	}
	return ntorV3ClientFromX(x, nodeID, ntorPub, extra, ver)
}

func ntorV3ClientFromX(x *KeyPair, nodeID [32]byte, ntorPub [32]byte, extra, ver []byte) ([]byte, *NtorV3ClientState, error) {
	bx, err := exp(x.Private[:], ntorPub[:])
	if err != nil {
		return nil, nil, err
	}
	encK, macK := ntorV3Phase1(bx, nodeID[:], x.Public[:], ntorPub[:], ver)
	encMsg, err := aes256CTR(encK, extra)
	if err != nil {
		return nil, nil, err
	}
	macIn := make([]byte, 0, EdIDLen+GLen+GLen+len(encMsg))
	macIn = append(macIn, nodeID[:]...)
	macIn = append(macIn, ntorPub[:]...)
	macIn = append(macIn, x.Public[:]...)
	macIn = append(macIn, encMsg...)
	msgMAC := mac3(tMsgMAC, macK, macIn)
	hs := make([]byte, 0, NtorV3MinH+len(encMsg))
	hs = append(hs, nodeID[:]...)
	hs = append(hs, ntorPub[:]...)
	hs = append(hs, x.Public[:]...)
	hs = append(hs, encMsg...)
	hs = append(hs, msgMAC...)
	st := &NtorV3ClientState{
		X:      x,
		ID:     nodeID,
		B:      ntorPub,
		Xpub:   x.Public[:],
		Bx:     bx,
		MsgMAC: msgMAC,
		VER:    append([]byte(nil), ver...),
	}
	return hs, st, nil
}

func (st *NtorV3ClientState) Finish(reply []byte) (*CircuitKeys, []byte, error) {
	if len(reply) < NtorV3MinR {
		return nil, nil, ErrNtorV3Len
	}
	Y := reply[:GLen]
	AUTH := reply[GLen : GLen+NtorV3MACLen]
	encSM := reply[GLen+NtorV3MACLen:]
	yx, err := exp(st.X.Private[:], Y)
	if err != nil {
		return nil, nil, err
	}
	keySeed, verify := ntorV3Secret(yx, st.Bx, st.ID[:], st.B[:], st.Xpub, Y, st.VER)
	auth := ntorV3Auth(verify, st.ID[:], st.B[:], Y, st.Xpub, st.MsgMAC, encSM)
	if !hmac.Equal(auth, AUTH) {
		return nil, nil, ErrNtorAuth
	}
	encKey, ks := ntorV3Expand(keySeed, SHA1Len+SHA1Len+AESKeyLen+AESKeyLen+SHA1Len)
	sm, err := aes256CTR(encKey, encSM)
	if err != nil {
		return nil, nil, err
	}
	return keysFromStream(ks), sm, nil
}

type NtorV3Server struct {
	ID  [32]byte
	Key *KeyPair
}

func (s *NtorV3Server) Reply(rand io.Reader, handshake, extra, ver []byte) (reply []byte, keys *CircuitKeys, clientExtra []byte, err error) {
	y, err := GenerateKeyPair(rand)
	if err != nil {
		return nil, nil, nil, err
	}
	return s.replyWithY(y, handshake, extra, ver)
}

func (s *NtorV3Server) replyWithY(y *KeyPair, handshake, extra, ver []byte) (reply []byte, keys *CircuitKeys, clientExtra []byte, err error) {
	if len(handshake) < NtorV3MinH {
		return nil, nil, nil, ErrNtorV3Len
	}
	id := handshake[:EdIDLen]
	keyID := handshake[EdIDLen : EdIDLen+GLen]
	X := handshake[EdIDLen+GLen : EdIDLen+GLen+GLen]
	encCM := handshake[EdIDLen+GLen+GLen : len(handshake)-NtorV3MACLen]
	msgMAC := handshake[len(handshake)-NtorV3MACLen:]
	if !hmac.Equal(id, s.ID[:]) {
		return nil, nil, nil, ErrNtorID
	}
	if !hmac.Equal(keyID, s.Key.Public[:]) {
		return nil, nil, nil, ErrNtorKey
	}
	xb, err := exp(s.Key.Private[:], X)
	if err != nil {
		return nil, nil, nil, err
	}
	encK, macK := ntorV3Phase1(xb, s.ID[:], X, s.Key.Public[:], ver)
	macIn := make([]byte, 0, EdIDLen+GLen+GLen+len(encCM))
	macIn = append(macIn, s.ID[:]...)
	macIn = append(macIn, s.Key.Public[:]...)
	macIn = append(macIn, X...)
	macIn = append(macIn, encCM...)
	if !hmac.Equal(mac3(tMsgMAC, macK, macIn), msgMAC) {
		return nil, nil, nil, ErrNtorV3MAC
	}
	clientExtra, err = aes256CTR(encK, encCM)
	if err != nil {
		return nil, nil, nil, err
	}
	if extra == nil {
		extra = CCResponseIfRequested(clientExtra)
	}
	xy, err := exp(y.Private[:], X)
	if err != nil {
		return nil, nil, nil, err
	}
	keySeed, verify := ntorV3Secret(xy, xb, s.ID[:], s.Key.Public[:], X, y.Public[:], ver)
	encKey, ks := ntorV3Expand(keySeed, SHA1Len+SHA1Len+AESKeyLen+AESKeyLen+SHA1Len)
	encSM, err := aes256CTR(encKey, extra)
	if err != nil {
		return nil, nil, nil, err
	}
	auth := ntorV3Auth(verify, s.ID[:], s.Key.Public[:], y.Public[:], X, msgMAC, encSM)
	keys = keysFromStream(ks)
	reply = make([]byte, 0, NtorV3MinR+len(encSM))
	reply = append(reply, y.Public[:]...)
	reply = append(reply, auth...)
	reply = append(reply, encSM...)
	return reply, keys, clientExtra, nil
}
