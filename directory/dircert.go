package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"strings"
	"time"
)

type DirKeyCert struct {
	Fingerprint string
	Published   time.Time
	Expires     time.Time
	Identity    *rsa.PublicKey
	Signing     *rsa.PublicKey
	Raw         string
}

func ParseDirKeyCerts(doc string) ([]*DirKeyCert, error) {
	const start = "dir-key-certificate-version 3"
	var out []*DirKeyCert
	for {
		i := strings.Index(doc, start)
		if i < 0 {
			break
		}
		doc = doc[i:]
		j := strings.Index(doc[len(start):], start)
		var raw string
		if j < 0 {
			raw = doc
			doc = ""
		} else {
			raw = doc[:len(start)+j]
			doc = doc[len(start)+j:]
		}
		c, err := parseDirKeyCert(raw)
		if err != nil {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no dir-key-certificate-version 3")
	}
	return out, nil
}

func parseDirKeyCert(raw string) (*DirKeyCert, error) {
	c := &DirKeyCert{Raw: raw}
	keys := ParseAuthorityKeys([]byte(raw))
	if len(keys) < 2 {
		return nil, fmt.Errorf("dir-key-certificate: need identity and signing keys")
	}
	c.Identity, c.Signing = keys[0], keys[1]
	for _, line := range strings.Split(raw, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		switch fields[0] {
		case "fingerprint":
			if len(fields) >= 2 {
				c.Fingerprint = strings.ToUpper(strings.ReplaceAll(fields[1], " ", ""))
			}
		case "dir-key-published":
			if len(fields) >= 3 {
				c.Published, _ = time.Parse("2006-01-02 15:04:05", fields[1]+" "+fields[2])
			}
		case "dir-key-expires":
			if len(fields) >= 3 {
				c.Expires, _ = time.Parse("2006-01-02 15:04:05", fields[1]+" "+fields[2])
			}
		}
	}
	if c.Fingerprint == "" {
		return nil, fmt.Errorf("dir-key-certificate: missing fingerprint")
	}
	if got := rsaSHA1Hex(c.Identity); !strings.EqualFold(got, c.Fingerprint) {
		return nil, fmt.Errorf("dir-key-certificate: fingerprint %s != key digest %s", c.Fingerprint, got)
	}
	if err := verifyDirKeyCertification(raw, c.Identity); err != nil {
		return nil, err
	}
	if err := verifyDirKeyCrosscert(raw, c); err != nil {
		return nil, err
	}
	return c, nil
}

func verifyDirKeyCertification(raw string, ident *rsa.PublicKey) error {
	const kw = "dir-key-certification"
	i := strings.LastIndex(raw, kw)
	if i < 0 {
		return fmt.Errorf("dir-key-certificate: missing certification")
	}
	nl := strings.Index(raw[i:], "\n")
	if nl < 0 {
		return fmt.Errorf("dir-key-certificate: truncated certification")
	}
	lineEnd := i + nl
	begin := strings.Index(raw[lineEnd:], "-----BEGIN SIGNATURE-----")
	end := strings.Index(raw[lineEnd:], "-----END SIGNATURE-----")
	if begin < 0 || end < 0 || end <= begin {
		return fmt.Errorf("dir-key-certificate: missing SIGNATURE object")
	}
	blob := raw[lineEnd+begin+len("-----BEGIN SIGNATURE-----") : lineEnd+end]
	sig, err := decodeB64Blob(blob)
	if err != nil {
		return fmt.Errorf("dir-key-certificate: signature: %w", err)
	}
	prefixes := []string{
		raw[:lineEnd+1],
		raw[:lineEnd] + " ",
	}
	var last error
	for _, p := range prefixes {
		sum := sha1.Sum([]byte(p))
		if err := rsa.VerifyPKCS1v15(ident, 0, sum[:], sig); err == nil {
			return nil
		} else {
			last = err
		}
	}
	return fmt.Errorf("dir-key-certification: %w", last)
}

func verifyDirKeyCrosscert(raw string, c *DirKeyCert) error {
	const beginKw = "-----BEGIN ID SIGNATURE-----"
	const endKw = "-----END ID SIGNATURE-----"
	begin := strings.Index(raw, beginKw)
	end := strings.Index(raw, endKw)
	if begin < 0 || end < 0 || end <= begin {
		return fmt.Errorf("dir-key-certificate: missing crosscert")
	}
	sig, err := decodeB64Blob(raw[begin+len(beginKw) : end])
	if err != nil {
		return fmt.Errorf("dir-key-crosscert: %w", err)
	}
	sum := sha1.Sum(x509.MarshalPKCS1PublicKey(c.Identity))
	if err := rsa.VerifyPKCS1v15(c.Signing, 0, sum[:], sig); err != nil {
		return fmt.Errorf("dir-key-crosscert: %w", err)
	}
	return nil
}

func (c *DirKeyCert) ValidAt(now time.Time) error {
	skew := 24 * time.Hour
	if !c.Published.IsZero() && now.Add(skew).Before(c.Published) {
		return fmt.Errorf("dir-key-certificate %s not yet published", c.Fingerprint)
	}
	if !c.Expires.IsZero() && now.Add(-skew).After(c.Expires) {
		return fmt.Errorf("dir-key-certificate %s expired", c.Fingerprint)
	}
	return nil
}

func SignDirKeyCert(ident, signing *rsa.PrivateKey, published, expires string) (string, error) {
	fp := rsaSHA1Hex(&ident.PublicKey)
	identPEM := EncodeAuthorityKey(&ident.PublicKey)
	signPEM := EncodeAuthorityKey(&signing.PublicKey)
	idHash := sha1.Sum(x509.MarshalPKCS1PublicKey(&ident.PublicKey))
	cross, err := rsa.SignPKCS1v15(rand.Reader, signing, 0, idHash[:])
	if err != nil {
		return "", err
	}
	head := "dir-key-certificate-version 3\n" +
		"fingerprint " + fp + "\n" +
		"dir-key-published " + published + "\n" +
		"dir-key-expires " + expires + "\n" +
		"dir-identity-key\n" + string(identPEM) +
		"dir-signing-key\n" + string(signPEM) +
		"dir-key-crosscert\n-----BEGIN ID SIGNATURE-----\n" +
		wrap64(base64.StdEncoding.EncodeToString(cross)) +
		"-----END ID SIGNATURE-----\n" +
		"dir-key-certification\n"
	sum := sha1.Sum([]byte(head))
	sig, err := rsa.SignPKCS1v15(rand.Reader, ident, 0, sum[:])
	if err != nil {
		return "", err
	}
	return head + "-----BEGIN SIGNATURE-----\n" + wrap64(base64.StdEncoding.EncodeToString(sig)) + "-----END SIGNATURE-----\n", nil
}
