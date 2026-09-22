package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"time"

	"github.com/adam/gotor/crypto"
	"github.com/adam/gotor/directory"
)

func (c *Client) dialOnionPublic(host string, port uint16, pub ed25519.PublicKey) (*Stream, error) {
	intros, sub, err := c.fetchPublicIntros(pub)
	if err != nil {
		return nil, err
	}
	n := len(intros)
	if n > 4 {
		n = 4
	}
	var last error
	for i, intro := range intros[:n] {
		s, err := c.rendezvousPublic(host, port, intro, sub)
		if err == nil {
			return s, nil
		}
		last = err
		if c.Log != nil {
			c.Log.Info("intro attempt failed", "i", i, "addr", intro.Address, "port", intro.ORPort, "err", err)
		}
	}
	if last == nil {
		last = fmt.Errorf("no intro points")
	}
	return nil, last
}

func (c *Client) rendezvousPublic(host string, port uint16, intro *crypto.HSIntro, sub []byte) (*Stream, error) {
	ipRel := c.lookupOR(intro.Address, intro.ORPort, intro.OnionKey)
	if ipRel == nil {
		return nil, fmt.Errorf("unknown intro point")
	}
	rp := c.pickRendPublic(ipRel)
	if rp == nil {
		rp = pickWeighted(c.Relays, []*directory.Relay{ipRel})
	}
	if rp == nil {
		rp = c.pickRend(ipRel)
	}
	if rp == nil {
		return nil, fmt.Errorf("no rendezvous relay")
	}
	introPath, err := c.PickPathTo(ipRel)
	if err != nil {
		return nil, err
	}
	introCirc, err := c.BuildCircuit(introPath)
	if err != nil {
		return nil, err
	}
	defer introCirc.Close()
	rendPath, err := c.PickPathTo(rp)
	if err != nil {
		return nil, err
	}
	rendCirc, err := c.BuildCircuit(rendPath)
	if err != nil {
		return nil, err
	}
	cookie := make([]byte, 20)
	if _, err := io.ReadFull(rand.Reader, cookie); err != nil {
		rendCirc.Close()
		return nil, err
	}
	if err := rendCirc.EstablishRendezvous(cookie); err != nil {
		rendCirc.Close()
		return nil, err
	}
	st, err := introCirc.Introduce1RP(intro.AuthKey, intro.EncKey[:], sub, cookie, rp)
	if err != nil {
		rendCirc.Close()
		return nil, err
	}
	if err := rendCirc.WaitRendezvous2For(st, 25*time.Second); err != nil {
		rendCirc.Close()
		return nil, err
	}
	s, err := rendCirc.Dial(host, port)
	if err != nil {
		rendCirc.Close()
		return nil, err
	}
	return s, nil
}

func (c *Client) serveOnionPublic(body []byte) (string, error) {
	id, err := crypto.GenerateHSIdentity(rand.Reader)
	if err != nil {
		return "", err
	}
	authPub, authPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", err
	}
	enc, err := crypto.GenerateKeyPair(rand.Reader)
	if err != nil {
		return "", err
	}
	if len(c.Relays) == 0 {
		return "", fmt.Errorf("no relays")
	}
	ipRel := pickWeighted(c.Relays, nil)
	if ipRel == nil {
		return "", fmt.Errorf("no intro relay")
	}
	path, err := c.PickPathTo(ipRel)
	if err != nil {
		return "", err
	}
	introCirc, err := c.BuildCircuit(path)
	if err != nil {
		return "", err
	}
	if err := introCirc.EstablishIntro(authPriv); err != nil {
		introCirc.Close()
		return "", err
	}
	period := c.hsPeriod()
	blind, err := crypto.BlindPublic(id.Public, period, crypto.HSPeriodLength)
	if err != nil {
		introCirc.Close()
		return "", err
	}
	sub := crypto.Subcredential(id.Public, blind)
	descIntro := crypto.HSIntro{
		Address:  ipRel.Address,
		ORPort:   ipRel.ORPort,
		OnionKey: ipRel.NTorOnionKey,
		EncKey:   enc.Public,
		AuthKey:  authPub,
	}
	rev := uint64(time.Now().Unix())
	doc, err := crypto.BuildHSDescAt(rand.Reader, id, descIntro, rev, period, crypto.HSPeriodLength)
	if err != nil {
		introCirc.Close()
		return "", err
	}
	if err := c.publishPublicHS(blind, doc); err != nil {
		introCirc.Close()
		return "", err
	}
	go c.onionLoop(introCirc, enc.Private[:], authPub, sub, body)
	return crypto.OnionAddress(id.Public), nil
}

func (c *Client) fetchPublicIntros(pub ed25519.PublicKey) ([]*crypto.HSIntro, []byte, error) {
	if err := c.ensureHSDirMicros(); err != nil {
		return nil, nil, err
	}
	period := c.hsPeriod()
	attempts := []struct {
		period uint64
		srv    []byte
	}{
		{period, c.hsSRV(period, false)},
	}
	if period > 0 {
		attempts = append(attempts, struct {
			period uint64
			srv    []byte
		}{period - 1, c.hsSRV(period-1, true)})
	}
	var last error
	for _, a := range attempts {
		blind, err := crypto.BlindPublic(pub, a.period, crypto.HSPeriodLength)
		if err != nil {
			last = err
			continue
		}
		doc, err := c.fetchHSDescFromDirs(blind, a.period, a.srv)
		if err != nil {
			last = err
			continue
		}
		intros, err := crypto.ParseHSDescIntrosAt(doc, pub, a.period, crypto.HSPeriodLength)
		if err != nil {
			last = err
			continue
		}
		if c.Log != nil {
			c.Log.Info("fetched hs descriptor", "intros", len(intros), "period", a.period)
		}
		return intros, crypto.Subcredential(pub, blind), nil
	}
	if last == nil {
		last = directory.ErrHSNotFound
	}
	return nil, nil, last
}

func (c *Client) fetchHSDescFromDirs(blinded ed25519.PublicKey, period uint64, srv []byte) (string, error) {
	dirs := directory.ResponsibleHSDirs(c.hsdirs(), blinded, srv, period, crypto.HSSpreadFetch)
	if len(dirs) == 0 {
		return "", fmt.Errorf("no responsible hsdirs")
	}
	id := crypto.BlindedURLID(blinded)
	var last error
	for _, d := range dirs {
		if d.NTorOnionKey == [32]byte{} {
			continue
		}
		doc, err := c.beginDirGet(d, "/tor/hs/3/"+id)
		if err != nil {
			last = err
			if c.Log != nil {
				c.Log.Info("hsdir fetch failed", "relay", d.Nickname, "err", err)
			}
			continue
		}
		return doc, nil
	}
	if last == nil {
		last = directory.ErrHSNotFound
	}
	return "", last
}

func (c *Client) publishPublicHS(blinded ed25519.PublicKey, doc string) error {
	if err := c.ensureHSDirMicros(); err != nil {
		return err
	}
	period := c.hsPeriod()
	srv := c.hsSRV(period, false)
	dirs := directory.ResponsibleHSDirs(c.hsdirs(), blinded, srv, period, crypto.HSSpreadStore)
	if len(dirs) == 0 {
		return fmt.Errorf("no responsible hsdirs")
	}
	id := crypto.BlindedURLID(blinded)
	var last error
	ok := 0
	for _, d := range dirs {
		if d.NTorOnionKey == [32]byte{} {
			continue
		}
		if err := c.beginDirPost(d, "/tor/hs/3/"+id, doc); err != nil {
			last = err
			if c.Log != nil {
				c.Log.Info("hsdir publish failed", "relay", d.Nickname, "err", err)
			}
			continue
		}
		ok++
	}
	if ok == 0 {
		if last == nil {
			last = fmt.Errorf("hsdir publish failed")
		}
		return last
	}
	return nil
}

func (c *Client) beginDirGet(r *directory.Relay, path string) (string, error) {
	p, err := c.PickPathTo(r)
	if err != nil {
		return "", err
	}
	circ, err := c.BuildCircuit(p)
	if err != nil {
		return "", err
	}
	defer circ.Close()
	st, err := circ.DialDir()
	if err != nil {
		return "", err
	}
	defer st.Close()
	return directory.HTTPGet(st, path)
}

func (c *Client) beginDirPost(r *directory.Relay, path, body string) error {
	p, err := c.PickPathTo(r)
	if err != nil {
		return err
	}
	circ, err := c.BuildCircuit(p)
	if err != nil {
		return err
	}
	defer circ.Close()
	st, err := circ.DialDir()
	if err != nil {
		return err
	}
	defer st.Close()
	return directory.HTTPPost(st, path, body)
}

func (c *Client) ensureHSDirMicros() error {
	c.hsdirOnce.Do(func() {
		if c.DirHTTP == "" {
			c.hsdirErr = fmt.Errorf("no directory HTTP address")
			return
		}
		var need []*directory.Relay
		for _, r := range c.All {
			if r == nil || !r.Has("HSDir") || !r.Has("Running") || !r.Has("Valid") {
				continue
			}
			if len(r.MicroHash) != 32 {
				continue
			}
			need = append(need, r)
		}
		if c.Log != nil {
			c.Log.Info("fetching hsdir microdescriptors", "n", len(need))
		}
		c.hsdirErr = directory.FetchMicros(c.DirHTTP, need)
	})
	return c.hsdirErr
}

func (c *Client) hsdirs() []*directory.Relay {
	src := c.All
	if len(src) == 0 {
		src = c.Relays
	}
	var out []*directory.Relay
	for _, r := range src {
		if r != nil && r.Has("HSDir") && len(r.Ed25519ID) == 32 {
			out = append(out, r)
		}
	}
	return out
}

func (c *Client) hsPeriod() uint64 {
	t := c.ValidAfter
	if t.IsZero() {
		t = time.Now()
	}
	return crypto.TimePeriodNum(t)
}

func (c *Client) hsSRV(period uint64, prev bool) []byte {
	if prev && len(c.PrevSRV) == 32 {
		return c.PrevSRV
	}
	if !prev && len(c.SRV) == 32 {
		return c.SRV
	}
	if len(c.SRV) == 32 {
		return c.SRV
	}
	return crypto.DisasterSRV(crypto.HSPeriodLength, period)
}
