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
	keys := ParseAuthorityKeys([]byte(keyPEM))
	if len(keys) == 0 {
		return "", fmt.Errorf("authority key: no PEM block")
	}
	cons, err := get(c, "http://"+dirAddr+path)
	if err != nil {
		return "", err
	}
	var last error
	for _, pub := range keys {
		if err := VerifyConsensus(cons, pub); err == nil {
			return cons, nil
		} else {
			last = err
		}
	}
	if last == nil {
		last = fmt.Errorf("no authority key")
	}
	return "", last
}
