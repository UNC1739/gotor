package directory

import (
	"fmt"
	"net/http"
)

func fetchSignedConsensus(c *http.Client, dirAddr, path string) (string, error) {
	keyPEM, err := get(c, "http://"+dirAddr+"/tor/keys/authority")
	if err != nil {
		return "", fmt.Errorf("authority key: %w", err)
	}
	pub, err := ParseAuthorityKey([]byte(keyPEM))
	if err != nil {
		return "", err
	}
	cons, err := get(c, "http://"+dirAddr+path)
	if err != nil {
		return "", err
	}
	if err := VerifyConsensus(cons, pub); err != nil {
		return "", err
	}
	return cons, nil
}
