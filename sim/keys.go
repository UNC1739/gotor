package sim

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"

	"github.com/adam/gotor/certs"
	gtcrypto "github.com/adam/gotor/crypto"
	"github.com/adam/gotor/proto"
)

type RelayKeys struct {
	Nickname     string
	Flags        []string
	Listen       string
	AdvertiseIP  net.IP
	ORPort       uint16
	RSA          *rsa.PrivateKey
	Identity     [20]byte
	EdIDPub      ed25519.PublicKey
	EdIDPriv     ed25519.PrivateKey
	EdSignPub    ed25519.PublicKey
	EdSignPriv   ed25519.PrivateKey
	NTor         *gtcrypto.KeyPair
	TLS          *tls.Certificate
	TLSCertDER   []byte
}

func generateRelayKeys(nickname string, flags []string, advertise net.IP, hosts []string) (*RelayKeys, error) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("rsa: %w", err)
	}
	der := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	fp := sha1.Sum(der)
	idPub, idPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	signPub, signPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ntor, err := gtcrypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		return nil, err
	}
	var ips [][]byte
	if v4 := advertise.To4(); v4 != nil {
		ips = append(ips, append([]byte(nil), v4...))
	}
	ips = append(ips, net.ParseIP("127.0.0.1").To4())
	tlsCert, tlsDER, err := certs.SelfSignedTLS(hosts, ips)
	if err != nil {
		return nil, err
	}
	k := &RelayKeys{
		Nickname:    nickname,
		Flags:       flags,
		AdvertiseIP: advertise,
		RSA:         rsaKey,
		EdIDPub:     idPub,
		EdIDPriv:    idPriv,
		EdSignPub:   signPub,
		EdSignPriv:  signPriv,
		NTor:        ntor,
		TLS:         tlsCert,
		TLSCertDER:  tlsDER,
	}
	copy(k.Identity[:], fp[:])
	return k, nil
}

func (k *RelayKeys) Responder() proto.ResponderKeys {
	var adv [4]byte
	if v4 := k.AdvertiseIP.To4(); v4 != nil {
		copy(adv[:], v4)
	}
	return proto.ResponderKeys{
		IDPub:      k.EdIDPub,
		IDPriv:     k.EdIDPriv,
		SignPub:    k.EdSignPub,
		SignPriv:   k.EdSignPriv,
		TLSCertDER: k.TLSCertDER,
		Advertise:  adv,
	}
}

func (k *RelayKeys) TLSConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{*k.TLS},
		MinVersion:   tls.VersionTLS12,
	}
}
