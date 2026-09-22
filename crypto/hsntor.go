package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	hsNtorProto = "tor-hs-ntor-curve25519-sha3-256-1"
	tHsEnc      = hsNtorProto + ":hs_key_extract"
	tHsVerify   = hsNtorProto + ":hs_verify"
	tHsMAC      = hsNtorProto + ":hs_mac"
	mHsExpand   = hsNtorProto + ":hs_key_expand"
	introMACLen = 32
	introKeyLen = 32
	hsSHA3Len   = 32
	hsAESLen    = 32
)

type HSNtorClient struct {
	x, X, B, auth, sub, expBx []byte
}

type HSNtorServer struct {
	Handshake []byte
	Keys      *CircuitKeys
}

func IntroHandshakeMAC(kh, msg []byte) []byte {
	m := hmac.New(sha3.New256, kh)
	m.Write(msg)
	return m.Sum(nil)
}

// macSHA3 is C-Tor crypto_mac_sha3_256: SHA3-256(be64(len(key)) || key || msg).
func macSHA3(key, msg []byte) []byte {
	h := sha3.New256()
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(key)))
	h.Write(n[:])
	h.Write(key)
	h.Write(msg)
	return h.Sum(nil)
}

func introduceMACInput(authKey, clientPK, enc []byte) []byte {
	buf := make([]byte, 0, 20+1+2+len(authKey)+1+len(clientPK)+len(enc))
	buf = append(buf, make([]byte, 20)...)
	buf = append(buf, 0x02)
	var ln [2]byte
	binary.BigEndian.PutUint16(ln[:], uint16(len(authKey)))
	buf = append(buf, ln[:]...)
	buf = append(buf, authKey...)
	buf = append(buf, 0)
	buf = append(buf, clientPK...)
	buf = append(buf, enc...)
	return buf
}

func IntroduceEncrypt(encPubB, authKey, subcred, plaintext []byte) ([]byte, error) {
	blob, _, err := IntroduceEncryptClient(encPubB, authKey, subcred, plaintext)
	return blob, err
}

func IntroduceEncryptClient(encPubB, authKey, subcred, plaintext []byte) ([]byte, *HSNtorClient, error) {
	x, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	secret, err := exp(x.Private[:], encPubB)
	if err != nil {
		return nil, nil, err
	}
	encKey, macKey := hsIntroKeys(secret, authKey, x.Public[:], encPubB, subcred)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	enc := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(enc, plaintext)
	mac := macSHA3(macKey, introduceMACInput(authKey, x.Public[:], enc))
	out := make([]byte, 0, 32+len(enc)+introMACLen)
	out = append(out, x.Public[:]...)
	out = append(out, enc...)
	out = append(out, mac...)
	st := &HSNtorClient{
		x:     append([]byte(nil), x.Private[:]...),
		X:     append([]byte(nil), x.Public[:]...),
		B:     append([]byte(nil), encPubB...),
		auth:  append([]byte(nil), authKey...),
		sub:   append([]byte(nil), subcred...),
		expBx: secret,
	}
	return out, st, nil
}

func IntroduceDecrypt(encPrivB, authKey, subcred, encrypted []byte) ([]byte, error) {
	pt, _, err := IntroduceDecryptServer(encPrivB, authKey, subcred, encrypted)
	return pt, err
}

func IntroduceDecryptServer(encPrivB, authKey, subcred, encrypted []byte) ([]byte, *HSNtorServer, error) {
	if len(encrypted) < 32+introMACLen {
		return nil, nil, fmt.Errorf("short INTRODUCE encrypted")
	}
	clientPK := encrypted[:32]
	mac := encrypted[len(encrypted)-introMACLen:]
	enc := encrypted[32 : len(encrypted)-introMACLen]
	secret, err := exp(encPrivB, clientPK)
	if err != nil {
		return nil, nil, err
	}
	encPubB, err := curve25519.X25519(encPrivB, curve25519.Basepoint)
	if err != nil {
		return nil, nil, err
	}
	encKey, macKey := hsIntroKeys(secret, authKey, clientPK, encPubB, subcred)
	macIn := introduceMACInput(authKey, clientPK, enc)
	if !hmac.Equal(mac, macSHA3(macKey, macIn)) {
		return nil, nil, fmt.Errorf("INTRODUCE mac")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	pt := make([]byte, len(enc))
	cipher.NewCTR(block, iv).XORKeyStream(pt, enc)

	y, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	xy, err := exp(y.Private[:], clientPK)
	if err != nil {
		return nil, nil, err
	}
	keys, authMAC, err := hsRendKeys(xy, secret, authKey, encPubB, clientPK, y.Public[:])
	if err != nil {
		return nil, nil, err
	}
	hs := append(append([]byte(nil), y.Public[:]...), authMAC...)
	return pt, &HSNtorServer{Handshake: hs, Keys: keys}, nil
}

func (st *HSNtorClient) Finish(handshake []byte) (*CircuitKeys, error) {
	if st == nil || len(handshake) < 64 {
		return nil, fmt.Errorf("short RENDEZVOUS2 handshake")
	}
	Y := handshake[:32]
	got := handshake[32:64]
	xy, err := exp(st.x, Y)
	if err != nil {
		return nil, err
	}
	keys, authMAC, err := hsRendKeys(xy, st.expBx, st.auth, st.B, st.X, Y)
	if err != nil {
		return nil, err
	}
	if !hmac.Equal(got, authMAC) {
		return nil, fmt.Errorf("RENDEZVOUS AUTH")
	}
	return keys, nil
}

func hsRendKeys(xy, xb, auth, B, X, Y []byte) (*CircuitKeys, []byte, error) {
	secret := append(append(append(append(append(append(append([]byte{}, xy...), xb...), auth...), B...), X...), Y...), hsNtorProto...)
	seed := macSHA3(secret, []byte(tHsEnc))
	verify := macSHA3(secret, []byte(tHsVerify))
	authIn := append(append(append(append(append(append(append([]byte{}, verify...), auth...), B...), Y...), X...), hsNtorProto...), []byte("Server")...)
	authMAC := macSHA3(authIn, []byte(tHsMAC))
	h := sha3.NewShake256()
	h.Write(seed)
	h.Write([]byte(mHsExpand))
	out := make([]byte, hsSHA3Len*2+hsAESLen*2)
	_, _ = h.Read(out)
	keys := &CircuitKeys{
		Df: out[0:32],
		Db: out[32:64],
		Kf: out[64:96],
		Kb: out[96:128],
	}
	return keys, authMAC, nil
}

func hsIntroKeys(expBx, authKey, X, B, subcred []byte) (encKey, macKey []byte) {
	in := append(append(append(append(append([]byte{}, expBx...), authKey...), X...), B...), hsNtorProto...)
	in = append(in, tHsEnc...)
	in = append(in, mHsExpand...)
	in = append(in, subcred...)
	h := sha3.NewShake256()
	h.Write(in)
	keys := make([]byte, introKeyLen+introMACLen)
	_, _ = h.Read(keys)
	return keys[:introKeyLen], keys[introKeyLen:]
}
