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
	alg, sig, prefixes, err := consensusSigMaterial(doc)
	if err != nil {
		return err
	}
	var last error
	for _, prefix := range prefixes {
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
		if err := rsa.VerifyPKCS1v15(pub, 0, digest, sig); err == nil {
			return nil
		} else {
			last = err
		}
	}
	if last == nil {
		last = fmt.Errorf("directory-signature: no prefix")
	}
	return fmt.Errorf("directory-signature: %w", last)
}

func splitDirectorySignature(doc string) (prefix, alg string, sig []byte, err error) {
	alg, sig, prefixes, err := consensusSigMaterial(doc)
	if err != nil {
		return "", "", nil, err
	}
	if len(prefixes) == 0 {
		return "", "", nil, fmt.Errorf("missing directory-signature")
	}
	return prefixes[0], alg, sig, nil
}

func consensusSigMaterial(doc string) (alg string, sig []byte, prefixes []string, err error) {
	const kw = "directory-signature "
	i := strings.LastIndex(doc, "\n"+kw)
	start := 0
	if i >= 0 {
		start = i + 1
	} else if !strings.HasPrefix(doc, kw) {
		return "", nil, nil, fmt.Errorf("missing directory-signature")
	}
	nl := strings.Index(doc[start:], "\n")
	if nl < 0 {
		return "", nil, nil, fmt.Errorf("truncated directory-signature")
	}
	line := doc[start : start+nl]
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return "", nil, nil, fmt.Errorf("short directory-signature")
	}
	alg = "sha1"
	if len(fields) >= 4 {
		alg = fields[1]
	}
	begin := strings.Index(doc[start+nl:], "-----BEGIN SIGNATURE-----")
	end := strings.Index(doc[start+nl:], "-----END SIGNATURE-----")
	if begin < 0 || end < 0 || end <= begin {
		return "", nil, nil, fmt.Errorf("missing SIGNATURE object")
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
		return "", nil, nil, fmt.Errorf("signature base64: %w", err)
	}
	prefixes = []string{doc[:start] + line + " "}
	if j := strings.Index(doc, "network-status-version"); j >= 0 {
		k := strings.Index(doc[j:], "\ndirectory-signature")
		if k >= 0 {
			off := j + k + len("\ndirectory-signature")
			if off < len(doc) && doc[off] == ' ' {
				off++
			}
			prefixes = append(prefixes, doc[j:off])
		}
	}
	return alg, raw, prefixes, nil
}

func ParseAuthorityKey(pemBytes []byte) (*rsa.PublicKey, error) {
	keys := ParseAuthorityKeys(pemBytes)
	if len(keys) == 0 {
		return nil, fmt.Errorf("no PEM block")
	}
	return keys[len(keys)-1], nil
}

func ParseAuthorityKeys(pemBytes []byte) []*rsa.PublicKey {
	var keys []*rsa.PublicKey
	rest := pemBytes
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "RSA PUBLIC KEY" && block.Type != "PUBLIC KEY" {
			continue
		}
		if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
			keys = append(keys, pub)
			continue
		}
		if k, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if pub, ok := k.(*rsa.PublicKey); ok {
				keys = append(keys, pub)
			}
		}
	}
	return keys
}

func EncodeAuthorityKey(pub *rsa.PublicKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(pub)})
}
