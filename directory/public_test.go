package directory

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testAuth struct {
	ident, signing *rsa.PrivateKey
	cert           string
	a              Authority
}

func makeTestAuth(t *testing.T, nick string) testAuth {
	t.Helper()
	ident, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	signing, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignDirKeyCert(ident, signing, "2026-01-01 00:00:00", "2028-01-01 00:00:00")
	if err != nil {
		t.Fatal(err)
	}
	return testAuth{
		ident: ident, signing: signing, cert: cert,
		a: Authority{Nickname: nick, V3Ident: rsaSHA1Hex(&ident.PublicKey)},
	}
}

func signPayload(payload string, ident *rsa.PublicKey, signing *rsa.PrivateKey) string {
	header := fmt.Sprintf("directory-signature sha256 %s %s", rsaSHA1Hex(ident), rsaSHA1Hex(&signing.PublicKey))
	sum := sha256.Sum256([]byte(payload + header + " "))
	sig, err := rsa.SignPKCS1v15(rand.Reader, signing, 0, sum[:])
	if err != nil {
		panic(err)
	}
	return header + "\n-----BEGIN SIGNATURE-----\n" + wrap64(base64.StdEncoding.EncodeToString(sig)) + "-----END SIGNATURE-----\n"
}

func TestVerifyConsensusQuorum(t *testing.T) {
	a1 := makeTestAuth(t, "a1")
	a2 := makeTestAuth(t, "a2")
	a3 := makeTestAuth(t, "a3")
	payload := "network-status-version 3 microdesc\nvote-status consensus\ndirectory-footer\n"
	doc := payload + signPayload(payload, &a1.ident.PublicKey, a1.signing) + signPayload(payload, &a2.ident.PublicKey, a2.signing)
	signing := map[string]*rsa.PublicKey{
		a1.a.V3Ident: &a1.signing.PublicKey,
		a2.a.V3Ident: &a2.signing.PublicKey,
		a3.a.V3Ident: &a3.signing.PublicKey,
	}
	if err := VerifyConsensusQuorum(doc, signing, 3); err != nil {
		t.Fatal(err)
	}
	one := payload + signPayload(payload, &a1.ident.PublicKey, a1.signing)
	if err := VerifyConsensusQuorum(one, signing, 3); err == nil {
		t.Fatal("expected quorum failure")
	}
}

func TestFetchPublicFrom(t *testing.T) {
	a1 := makeTestAuth(t, "a1")
	a2 := makeTestAuth(t, "a2")
	a3 := makeTestAuth(t, "a3")
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ntor[0] = 2
	ed := make([]byte, 32)
	ed[0] = 3
	micro := "onion-key\nntor-onion-key " + B64(ntor) + "\nid ed25519 " + B64(ed) + "\np accept 1-65535\n"
	sum := sha256.Sum256([]byte(micro))
	payload := "network-status-version 3 microdesc\nvote-status consensus\n" +
		"r gotor1 " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast Exit\n" +
		"m " + B64(sum[:]) + "\n" +
		"directory-footer\n"
	cons := payload +
		signPayload(payload, &a1.ident.PublicKey, a1.signing) +
		signPayload(payload, &a2.ident.PublicKey, a2.signing)
	keys := a1.cert + a2.cert + a3.cert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/tor/keys/all":
			_, _ = w.Write([]byte(keys))
		case r.URL.Path == "/tor/status-vote/current/consensus-microdesc":
			_, _ = w.Write([]byte(cons))
		case strings.HasPrefix(r.URL.Path, "/tor/micro/d/"):
			_, _ = w.Write([]byte(micro))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	auths := []Authority{a1.a, a2.a, a3.a}
	relays, err := FetchPublicFrom(auths, host)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 || relays[0].Nickname != "gotor1" || relays[0].NTorOnionKey[0] != 2 {
		t.Fatalf("%+v", relays[0])
	}
}

func TestFetchPublicQuorumRejected(t *testing.T) {
	a1 := makeTestAuth(t, "a1")
	a2 := makeTestAuth(t, "a2")
	a3 := makeTestAuth(t, "a3")
	payload := "network-status-version 3 microdesc\nvote-status consensus\n" +
		"r gotor1 " + B64(make([]byte, 20)) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Running Valid\ndirectory-footer\n"
	cons := payload + signPayload(payload, &a1.ident.PublicKey, a1.signing)
	keys := a1.cert + a2.cert + a3.cert
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tor/keys/all":
			_, _ = w.Write([]byte(keys))
		case "/tor/status-vote/current/consensus-microdesc":
			_, _ = w.Write([]byte(cons))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")
	if _, err := FetchPublicFrom([]Authority{a1.a, a2.a, a3.a}, host); err == nil {
		t.Fatal("expected quorum rejection")
	}
}

func TestQuorumCount(t *testing.T) {
	if Quorum(9) != 5 || Quorum(3) != 2 || Quorum(1) != 1 {
		t.Fatalf("quorum %d %d %d", Quorum(9), Quorum(3), Quorum(1))
	}
}
