package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"strings"
)

func rsaSHA1Hex(pub *rsa.PublicKey) string {
	sum := sha1.Sum(x509.MarshalPKCS1PublicKey(pub))
	return strings.ToUpper(hex.EncodeToString(sum[:]))
}

func wrap64(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i += 64 {
		j := i + 64
		if j > len(s) {
			j = len(s)
		}
		b.WriteString(s[i:j])
		b.WriteByte('\n')
	}
	return b.String()
}

func SignConsensus(body string, key *rsa.PrivateKey) (string, error) {
	if !strings.HasSuffix(body, "\n") {
		body += "\n"
	}
	id := rsaSHA1Hex(&key.PublicKey)
	header := fmt.Sprintf("directory-signature sha256 %s %s", id, id)
	sum := sha256.Sum256([]byte(body + header + " "))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, 0, sum[:])
	if err != nil {
		return "", err
	}
	return body + header + "\n-----BEGIN SIGNATURE-----\n" + wrap64(base64.StdEncoding.EncodeToString(sig)) + "-----END SIGNATURE-----\n", nil
}

func VerifyConsensus(doc string, pub *rsa.PublicKey) error {
	prefix, alg, sig, err := splitDirectorySignature(doc)
	if err != nil {
		return err
	}
	var digest []byte
	switch alg {
	case "", "sha1":
		h := sha1.Sum([]byte(prefix))
		digest = h[:]
	case "sha256":
		h := sha256.Sum256([]byte(prefix))
		digest = h[:]
	default:
		return fmt.Errorf("unrecognized directory-signature algorithm %q", alg)
	}
	if err := rsa.VerifyPKCS1v15(pub, 0, digest, sig); err != nil {
		return fmt.Errorf("directory-signature: %w", err)
	}
	return nil
}

func splitDirectorySignature(doc string) (prefix, alg string, sig []byte, err error) {
	const kw = "directory-signature "
	i := strings.LastIndex(doc, "\n"+kw)
	start := 0
	if i >= 0 {
		start = i + 1
	} else if !strings.HasPrefix(doc, kw) {
		return "", "", nil, fmt.Errorf("missing directory-signature")
	}
	nl := strings.Index(doc[start:], "\n")
	if nl < 0 {
		return "", "", nil, fmt.Errorf("truncated directory-signature")
	}
	line := doc[start : start+nl]
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", "", nil, fmt.Errorf("short directory-signature")
	}
	alg = "sha1"
	if len(fields) >= 4 {
		alg = fields[1]
	}
	prefix = doc[:start] + line + " "
	begin := strings.Index(doc[start+nl:], "-----BEGIN SIGNATURE-----")
	end := strings.Index(doc[start+nl:], "-----END SIGNATURE-----")
	if begin < 0 || end < 0 || end <= begin {
		return "", "", nil, fmt.Errorf("missing SIGNATURE object")
	}
	blob := doc[start+nl+begin+len("-----BEGIN SIGNATURE-----") : start+nl+end]
	blob = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\r' || r == ' ' || r == '\t' {
			return -1
		}
		return r
	}, blob)
	raw, err := base64.StdEncoding.DecodeString(blob)
	if err != nil {
		return "", "", nil, fmt.Errorf("signature base64: %w", err)
	}
	return prefix, alg, raw, nil
}

func ParseAuthorityKey(pemBytes []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block")
	}
	pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return pub, nil
}

func EncodeAuthorityKey(pub *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)})
}
