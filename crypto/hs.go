package crypto

import (
	"crypto/ed25519"
	"crypto/sha512"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/sha3"
)

const (
	HSVersion      = byte(3)
	HSPeriodLength = uint64(1440)
	HSPeriodNum    = uint64(1)
	HSPubLen       = 32
	onionChecksum  = ".onion checksum"
)

// Ed25519 basepoint as a decimal string, matching C-Tor str_ed25519_basepoint.
const ed25519Basepoint = "(15112221349535400772501151409588531511454012693041857206046113283949847762202, 46316835694926478169428394003475163141307993866256225615783033603165251855960)"

type HSIdentity struct {
	Public  ed25519.PublicKey
	Private ed25519.PrivateKey
}

func GenerateHSIdentity(r io.Reader) (*HSIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(r)
	if err != nil {
		return nil, err
	}
	return &HSIdentity{Public: pub, Private: priv}, nil
}

func OnionAddress(pub ed25519.PublicKey) string {
	if len(pub) != HSPubLen {
		return ""
	}
	raw := onionRaw(pub)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw)
	return strings.ToLower(enc) + ".onion"
}

func ParseOnionAddress(addr string) (ed25519.PublicKey, error) {
	addr = strings.ToLower(strings.TrimSpace(addr))
	if !strings.HasSuffix(addr, ".onion") {
		return nil, fmt.Errorf("not an onion address")
	}
	label := strings.TrimSuffix(addr, ".onion")
	if len(label) != 56 {
		return nil, fmt.Errorf("not a v3 onion address")
	}
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(label))
	if err != nil {
		return nil, fmt.Errorf("onion base32: %w", err)
	}
	if len(raw) != 35 || raw[34] != HSVersion {
		return nil, fmt.Errorf("bad onion encoding")
	}
	pub := ed25519.PublicKey(append([]byte(nil), raw[:32]...))
	want := onionRaw(pub)
	if raw[32] != want[32] || raw[33] != want[33] {
		return nil, fmt.Errorf("onion checksum")
	}
	return pub, nil
}

func onionRaw(pub ed25519.PublicKey) []byte {
	d := sha3.New256()
	d.Write([]byte(onionChecksum))
	d.Write(pub)
	d.Write([]byte{HSVersion})
	sum := d.Sum(nil)
	out := make([]byte, 35)
	copy(out, pub)
	copy(out[32:], sum[:2])
	out[34] = HSVersion
	return out
}

func Credential(pub ed25519.PublicKey) []byte {
	d := sha3.New256()
	d.Write([]byte("credential"))
	d.Write(pub)
	return d.Sum(nil)
}

func Subcredential(pub, blindedPub ed25519.PublicKey) []byte {
	cred := Credential(pub)
	d := sha3.New256()
	d.Write([]byte("subcredential"))
	d.Write(cred)
	d.Write(blindedPub)
	return d.Sum(nil)
}

func BlindPublic(pub ed25519.PublicKey, periodNum, periodLen uint64) (ed25519.PublicKey, error) {
	h, err := blindingScalar(pub, nil, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	A, err := new(edwards25519.Point).SetBytes(pub)
	if err != nil {
		return nil, fmt.Errorf("hs identity point: %w", err)
	}
	Aprime := new(edwards25519.Point).ScalarMult(h, A)
	return ed25519.PublicKey(Aprime.Bytes()), nil
}

func BlindPublicSim(pub ed25519.PublicKey) (ed25519.PublicKey, error) {
	return BlindPublic(pub, HSPeriodNum, HSPeriodLength)
}

func BlindSecret(priv ed25519.PrivateKey, periodNum, periodLen uint64) (pub ed25519.PublicKey, err error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("hs private key length")
	}
	idPub := priv.Public().(ed25519.PublicKey)
	h, err := blindingScalar(idPub, nil, periodNum, periodLen)
	if err != nil {
		return nil, err
	}
	wide := sha512.Sum512(priv.Seed())
	a, err := edwards25519.NewScalar().SetBytesWithClamping(wide[:32])
	if err != nil {
		return nil, err
	}
	aPrime := new(edwards25519.Scalar).Multiply(h, a)
	Aprime := new(edwards25519.Point).ScalarBaseMult(aPrime)
	return ed25519.PublicKey(Aprime.Bytes()), nil
}

func blindingScalar(pub ed25519.PublicKey, secret []byte, periodNum, periodLen uint64) (*edwards25519.Scalar, error) {
	if len(pub) != HSPubLen {
		return nil, fmt.Errorf("hs public key length")
	}
	n := make([]byte, 9+8+8)
	copy(n, "key-blind")
	binary.BigEndian.PutUint64(n[9:17], periodNum)
	binary.BigEndian.PutUint64(n[17:25], periodLen)

	d := sha3.New256()
	d.Write([]byte("Derive temporary signing key"))
	d.Write([]byte{0})
	d.Write(pub)
	d.Write(secret)
	d.Write([]byte(ed25519Basepoint))
	d.Write(n)
	sum := d.Sum(nil)
	return edwards25519.NewScalar().SetBytesWithClamping(sum)
}
