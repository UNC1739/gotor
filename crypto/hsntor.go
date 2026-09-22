package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/sha3"
)

const (
	hsNtorProto = "tor-hs-ntor-curve25519-sha3-256-1"
	tHsEnc      = hsNtorProto + ":hs_key_extract"
	mHsExpand   = hsNtorProto + ":hs_key_expand"
	introMACLen = 32
	introKeyLen = 32
)

func IntroHandshakeMAC(kh, msg []byte) []byte {
	m := hmac.New(sha3.New256, kh)
	m.Write(msg)
	return m.Sum(nil)
}

func IntroduceEncrypt(encPubB, authKey, subcred, plaintext []byte) ([]byte, error) {
	x, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}
	secret, err := exp(x.Private[:], encPubB)
	if err != nil {
		return nil, err
	}
	encKey, macKey := hsIntroKeys(secret, authKey, x.Public[:], encPubB, subcred)
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	enc := make([]byte, len(plaintext))
	cipher.NewCTR(block, iv).XORKeyStream(enc, plaintext)
	macIn := append(append(append([]byte{}, authKey...), 0), x.Public[:]...)
	macIn = append(macIn, enc...)
	m := hmac.New(sha3.New256, macKey)
	m.Write(macIn)
	out := make([]byte, 0, 32+len(enc)+introMACLen)
	out = append(out, x.Public[:]...)
	out = append(out, enc...)
	out = append(out, m.Sum(nil)...)
	return out, nil
}

func IntroduceDecrypt(encPrivB, authKey, subcred, encrypted []byte) ([]byte, error) {
	if len(encrypted) < 32+introMACLen {
		return nil, fmt.Errorf("short INTRODUCE encrypted")
	}
	clientPK := encrypted[:32]
	mac := encrypted[len(encrypted)-introMACLen:]
	enc := encrypted[32 : len(encrypted)-introMACLen]
	secret, err := exp(encPrivB, clientPK)
	if err != nil {
		return nil, err
	}
	encPubB, err := curve25519.X25519(encPrivB, curve25519.Basepoint)
	if err != nil {
		return nil, err
	}
	encKey, macKey := hsIntroKeys(secret, authKey, clientPK, encPubB, subcred)
	macIn := append(append(append([]byte{}, authKey...), 0), clientPK...)
	macIn = append(macIn, enc...)
	m := hmac.New(sha3.New256, macKey)
	m.Write(macIn)
	if !hmac.Equal(mac, m.Sum(nil)) {
		return nil, fmt.Errorf("INTRODUCE mac")
	}
	block, err := aes.NewCipher(encKey)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	pt := make([]byte, len(enc))
	cipher.NewCTR(block, iv).XORKeyStream(pt, enc)
	return pt, nil
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
