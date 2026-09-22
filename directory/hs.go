package directory

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

var ErrHSNotFound = errors.New("hsdesc not found")

func PublishHS(dirAddr, id, doc string) error {
	c := &http.Client{Timeout: 15 * time.Second}
	url := "http://" + dirAddr + "/tor/hs/3/" + id
	resp, err := c.Post(url, "text/plain", strings.NewReader(doc))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != 200 {
		return fmt.Errorf("publish %s: %s", url, resp.Status)
	}
	return nil
}

func FetchHS(dirAddr, id string) (string, error) {
	c := &http.Client{Timeout: 15 * time.Second}
	url := "http://" + dirAddr + "/tor/hs/3/" + id
	resp, err := c.Get(url)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return "", ErrHSNotFound
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("%s: %s", url, resp.Status)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	return string(b), nil
}
