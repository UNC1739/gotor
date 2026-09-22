package client

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/adam/gotor/cell"
	"github.com/adam/gotor/crypto"
	"github.com/adam/gotor/directory"
)

func (c *Client) DialOnion(host string, port uint16) (*Stream, error) {
	pub, err := crypto.ParseOnionAddress(host)
	if err != nil {
		return nil, err
	}
	if c.DirAddr == "public" {
		return c.dialOnionPublic(host, port, pub)
	}
	blind, err := crypto.BlindPublicSim(pub)
	if err != nil {
		return nil, err
	}
	doc, err := directory.FetchHS(c.DirAddr, crypto.HSDescID(blind))
	if err != nil {
		return nil, err
	}
	intro, err := crypto.ParseHSDesc(doc, pub)
	if err != nil {
		return nil, err
	}
	ipRel := c.relayByOR(intro.Address, intro.ORPort)
	if ipRel == nil {
		return nil, fmt.Errorf("unknown intro point")
	}
	rp := c.pickRend(ipRel)
	if rp == nil {
		return nil, fmt.Errorf("no rendezvous relay")
	}
	sub := crypto.Subcredential(pub, blind)
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
	if err := rendCirc.WaitRendezvous2(st); err != nil {
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

func (circ *Circuit) Introduce1RP(authKey, encPub, subcred, cookie []byte, rp *directory.Relay) (*crypto.HSNtorClient, error) {
	var ipv4 [4]byte
	if ip := rp.Address.To4(); ip != nil {
		copy(ipv4[:], ip)
	}
	pt := cell.EncodeIntroPlaintextIDs(cookie, rp.NTorOnionKey[:], ipv4, rp.ORPort, rp.Identity, rp.Ed25519ID)
	enc, st, err := crypto.IntroduceEncryptClient(encPub, authKey, subcred, pt)
	if err != nil {
		return nil, err
	}
	if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
		Command: cell.RelayIntroduce1,
		Data:    cell.EncodeIntroduce1(authKey, enc),
	}); err != nil {
		return nil, err
	}
	msg, err := circ.waitCtrl(cell.RelayIntroduceAck, 10*time.Second)
	if err != nil {
		return nil, err
	}
	ack, err := cell.ParseIntroduceAck(msg.Data)
	if err != nil {
		return nil, err
	}
	if ack != 0 {
		return nil, fmt.Errorf("INTRODUCE_ACK status %d", ack)
	}
	return st, nil
}

func (circ *Circuit) Accept() (*Stream, error) {
	t := time.NewTimer(15 * time.Second)
	defer t.Stop()
	select {
	case msg := <-circ.incoming:
		s := &Stream{id: msg.StreamID, circ: circ, pack: cell.StreamWindowStart, deliv: cell.StreamWindowStart}
		s.cond = sync.NewCond(&s.mu)
		circ.mu.Lock()
		circ.streams[msg.StreamID] = s
		circ.mu.Unlock()
		if err := circ.sendRelay(len(circ.hops)-1, cell.CmdRelay, cell.Relay{
			Command:  cell.RelayConnected,
			StreamID: msg.StreamID,
			Data:     make([]byte, 8),
		}); err != nil {
			return nil, err
		}
		return s, nil
	case <-circ.done:
		circ.mu.Lock()
		err := circ.dead
		circ.mu.Unlock()
		if err == nil {
			err = fmt.Errorf("circuit dead")
		}
		return nil, err
	case <-t.C:
		return nil, fmt.Errorf("timeout waiting for BEGIN")
	}
}

func (c *Client) ServeOnion(body []byte) (addr string, err error) {
	if c.DirAddr == "public" {
		return c.serveOnionPublic(body)
	}
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
	ipRel := c.Relays[len(c.Relays)-1]
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
	blind, err := crypto.BlindPublicSim(id.Public)
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
	doc, err := crypto.BuildHSDesc(rand.Reader, id, descIntro, 1)
	if err != nil {
		introCirc.Close()
		return "", err
	}
	if err := directory.PublishHS(c.DirAddr, crypto.HSDescID(blind), doc); err != nil {
		introCirc.Close()
		return "", err
	}
	go c.onionLoop(introCirc, enc.Private[:], authPub, sub, body)
	return crypto.OnionAddress(id.Public), nil
}

func (c *Client) onionLoop(introCirc *Circuit, encPriv, authKey, subcred, body []byte) {
	for {
		got, err := introCirc.WaitIntroduce2(encPriv, authKey, subcred)
		if err != nil {
			return
		}
		var onion [32]byte
		copy(onion[:], got.OnionKey)
		rp := c.lookupOR(got.Address, got.ORPort, onion)
		if rp == nil || got.Server == nil {
			continue
		}
		path, err := c.PickPathTo(rp)
		if err != nil {
			continue
		}
		rend, err := c.BuildCircuit(path)
		if err != nil {
			continue
		}
		if err := rend.Rendezvous1(got.Cookie, got.Server.Handshake); err != nil {
			rend.Close()
			continue
		}
		if err := rend.AttachHSHop(got.Server.Keys); err != nil {
			rend.Close()
			continue
		}
		st, err := rend.Accept()
		if err != nil {
			rend.Close()
			continue
		}
		buf := make([]byte, 1024)
		_, _ = st.Read(buf)
		_, _ = st.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\n\r\n"))
		_, _ = st.Write(body)
		_ = st.Close()
	}
}

func (c *Client) relayByOR(ip net.IP, port uint16) *directory.Relay {
	var found *directory.Relay
	c.eachRelay(func(r *directory.Relay) bool {
		if r.ORPort == port && r.Address.Equal(ip) {
			found = r
			return true
		}
		return false
	})
	return found
}

func (c *Client) relayByNTor(key []byte) *directory.Relay {
	if len(key) != 32 {
		return nil
	}
	var k [32]byte
	copy(k[:], key)
	var found *directory.Relay
	c.eachRelay(func(r *directory.Relay) bool {
		if r.NTorOnionKey == k {
			found = r
			return true
		}
		return false
	})
	return found
}

func (c *Client) eachRelay(fn func(*directory.Relay) bool) {
	seen := map[*directory.Relay]bool{}
	for _, r := range c.Relays {
		if r == nil || seen[r] {
			continue
		}
		seen[r] = true
		if fn(r) {
			return
		}
	}
	for _, r := range c.All {
		if r == nil || seen[r] {
			continue
		}
		seen[r] = true
		if fn(r) {
			return
		}
	}
}

func (c *Client) lookupOR(ip net.IP, port uint16, onion [32]byte) *directory.Relay {
	if r := c.relayByOR(ip, port); r != nil {
		if r.NTorOnionKey == [32]byte{} && onion != [32]byte{} {
			r.NTorOnionKey = onion
		}
		return r
	}
	if r := c.relayByNTor(onion[:]); r != nil {
		return r
	}
	if onion == [32]byte{} || ip == nil || port == 0 {
		return nil
	}
	return &directory.Relay{
		Nickname:     "hs-or",
		Address:      ip,
		ORPort:       port,
		NTorOnionKey: onion,
		Flags:        map[string]bool{"Running": true, "Valid": true},
	}
}

func (c *Client) pickRend(avoid *directory.Relay) *directory.Relay {
	for _, r := range c.Relays {
		if r != avoid {
			return r
		}
	}
	if len(c.Relays) > 0 {
		return c.Relays[0]
	}
	return nil
}

func (c *Client) pickRendPublic(avoid *directory.Relay) *directory.Relay {
	var cand []*directory.Relay
	for _, r := range c.Relays {
		if r == nil || r == avoid {
			continue
		}
		if r.Address.To4() == nil || r.Identity == [20]byte{} || r.NTorOnionKey == [32]byte{} {
			continue
		}
		if !r.Has("Running") && !r.Has("Fast") && !r.Has("Valid") {
			continue
		}
		cand = append(cand, r)
	}
	return pickWeighted(cand, nil)
}
