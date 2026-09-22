package crypto

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/adam/gotor/cell"
)

func TestIntroduceEncryptDecrypt(t *testing.T) {
	authPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	enc, err := GenerateKeyPair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sub := make([]byte, 32)
	cookie := bytes.Repeat([]byte{0x11}, 20)
	onion := bytes.Repeat([]byte{0x22}, 32)
	var ip [4]byte
	pt := cell.EncodeIntroPlaintext(cookie, onion, ip, 9001)
	blob, err := IntroduceEncrypt(enc.Public[:], authPub, sub, pt)
	if err != nil {
		t.Fatal(err)
	}
	got, err := IntroduceDecrypt(enc.Private[:], authPub, sub, blob)
	if err != nil {
		t.Fatal(err)
	}
	c2, o2, err := cell.ParseIntroPlaintext(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(c2, cookie) || !bytes.Equal(o2, onion) {
		t.Fatal("mismatch")
	}
	blob[40] ^= 0xff
	if _, err := IntroduceDecrypt(enc.Private[:], authPub, sub, blob); err == nil {
		t.Fatal("expected mac fail")
	}
}
