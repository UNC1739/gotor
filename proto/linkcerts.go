package proto

import (
	"crypto/ed25519"
	"crypto/rsa"

	"github.com/adam/gotor/certs"
)

func encodeLinkCERTS(idCert, other []byte, otherType byte, rsaKey *rsa.PrivateKey, edID ed25519.PublicKey) ([]byte, error) {
	entries := [][2][]byte{
		{{certs.CertTypeIdentityVSigning}, idCert},
		{{otherType}, other},
	}
	if rsaKey != nil {
		x509der, err := certs.EncodeRSAIdentityCert(rsaKey)
		if err != nil {
			return nil, err
		}
		cc, err := certs.EncodeRSAEdCrossCert(edID, rsaKey, 24*365*10)
		if err != nil {
			return nil, err
		}
		entries = append(entries,
			[2][]byte{{certs.CertTypeRSAIDX509}, x509der},
			[2][]byte{{certs.CertTypeRSAIDVIdentity}, cc},
		)
	}
	return certs.EncodeCERTS(entries), nil
}
