package directory

import (
	"crypto/sha256"
	"testing"
)

func TestParseConsensusAndDescriptors(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ntor[0] = 2
	ed := make([]byte, 32)
	ed[0] = 3
	cons := "network-status-version 3\nvote-status consensus\n" +
		"valid-after 2020-01-01 00:00:00\n" +
		"fresh-until 2020-01-01 01:00:00\n" +
		"valid-until 2020-01-01 03:00:00\n" +
		"known-flags Authority BadExit Exit Fast Guard HSDir Running Stable V2Dir Valid\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0 extra\n" +
		"s Guard Running Valid Fast\n" +
		"directory-footer\n" +
		"directory-signature moria1 9695DFC35FFEB861329B9F1AB04C46397020CE31\n-----BEGIN SIGNATURE-----\n-----END SIGNATURE-----\n"
	relays, err := ParseConsensus(cons)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 || relays[0].Nickname != "gotor1" || relays[0].ORPort != 9001 || !relays[0].Has("Guard") {
		t.Fatalf("%+v", relays[0])
	}
	desc := "router gotor1 10.0.0.2 9001 0 0\nfingerprint " + FingerprintHex(relays[0].Identity) +
		"\nntor-onion-key " + B64(ntor) + "\nmaster-key-ed25519 " + B64(ed) + "\naccept *:*\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 2 || !relays[0].ExitAccept || relays[0].Ed25519ID[0] != 3 {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseConsensusPAcceptPorts(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "r exit1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Exit Fast\n" +
		"p accept 80,443\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Exit") || !relays[0].ExitAccept {
		t.Fatalf("%+v %v", relays, err)
	}
}


func TestParseBandwidth(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	cons := "network-status-version 3\nvote-status consensus\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n" +
		"w Bandwidth=1234\n" +
		"directory-footer\n" +
		"bandwidth-weights Wgg=5000 Wee=9000\n"
	relays, err := ParseConsensus(cons)
	if err != nil {
		t.Fatal(err)
	}
	if relays[0].Bandwidth != 1234 {
		t.Fatalf("bandwidth %d", relays[0].Bandwidth)
	}
	w := ParseBandwidthWeights(cons)
	if w["Wgg"] != 5000 || w["Wee"] != 9000 {
		t.Fatalf("%v", w)
	}
}

func TestParseConsensusHeader(t *testing.T) {
	srv := make([]byte, 32)
	srv[0] = 9
	prev := make([]byte, 32)
	prev[0] = 8
	doc := "network-status-version 3 microdesc\n" +
		"valid-after 2026-09-22 12:00:00\n" +
		"shared-rand-previous-value 8 " + B64(prev) + "\n" +
		"shared-rand-current-value 8 " + B64(srv) + "\n" +
		"r gotor1 " + B64(make([]byte, 20)) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n"
	hdr := ParseConsensusHeader(doc)
	if hdr.ValidAfter.Year() != 2026 || hdr.ValidAfter.Month() != 9 || hdr.ValidAfter.Day() != 22 {
		t.Fatalf("valid-after %v", hdr.ValidAfter)
	}
	if len(hdr.SRV) != 32 || hdr.SRV[0] != 9 || hdr.PrevSRV[0] != 8 {
		t.Fatalf("%+v", hdr)
	}
}
func TestParseProto(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ed := make([]byte, 32)
	cons := "network-status-version 3\nvote-status consensus\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n" +
		"pr Relay=1-4 Link=1,3\n" +
		"directory-footer\n"
	relays, err := ParseConsensus(cons)
	if err != nil {
		t.Fatal(err)
	}
	if !relays[0].Supports("Relay", 4) || relays[0].Supports("Relay", 5) || !relays[0].Supports("Link", 3) {
		t.Fatalf("%v", relays[0].Proto)
	}
	desc := "router gotor1 10.0.0.2 9001 0 0\nfingerprint " + FingerprintHex(relays[0].Identity) +
		"\nntor-onion-key " + B64(ntor) + "\nmaster-key-ed25519 " + B64(ed) +
		"\nproto Relay=1-3\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].Supports("Relay", 4) || !relays[0].Supports("Relay", 3) {
		t.Fatalf("descriptor proto %v", relays[0].Proto)
	}
}

func TestParseMicrodescriptors(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ntor[0] = 2
	ed := make([]byte, 32)
	ed[0] = 3
	micro := "onion-key\nntor-onion-key " + B64(ntor) + "\nid ed25519 " + B64(ed) + "\np accept 1-65535\n"
	sum := sha256.Sum256([]byte(micro))
	cons := "network-status-version 3 microdesc\nvote-status consensus\n" +
		"r gotor1 " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n" +
		"m " + B64(sum[:]) + "\n" +
		"directory-footer\n"
	relays, err := ParseConsensus(cons)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 1 || relays[0].ORPort != 9001 || len(relays[0].MicroHash) != 32 {
		t.Fatalf("%+v", relays[0])
	}
	if err := ParseMicrodescriptors(micro, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 2 || relays[0].Ed25519ID[0] != 3 || !relays[0].ExitAccept {
		t.Fatalf("%+v", relays[0])
	}
}
func TestB64RoundTrip(t *testing.T) {
	in := make([]byte, 20)
	for i := range in {
		in[i] = byte(i * 3)
	}
	out, err := b64(B64(in), 20)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != string(in) {
		t.Fatalf("%x vs %x", out, in)
	}
}

func TestFingerprintFormat(t *testing.T) {
	var id [20]byte
	id[0] = 0xab
	id[1] = 0xcd
	s := FingerprintHex(id)
	if s[:4] != "ABCD" {
		t.Fatal(s)
	}
	if FingerprintCompact(id)[:4] != "ABCD" {
		t.Fatal(FingerprintCompact(id))
	}
}

func TestShortRLine(t *testing.T) {
	if _, err := ParseConsensus("r nick only\n"); err == nil {
		t.Fatal("expected error")
	}
}

func TestParseConsensusMultipleRelays(t *testing.T) {
	id1 := make([]byte, 20)
	id1[0] = 1
	id2 := make([]byte, 20)
	id2[0] = 2
	cons := "network-status-version 3\nvote-status consensus\n" +
		"r gotor1 " + B64(id1) + " " + B64(id1) + " 2020-01-01 00:00:00 10.0.0.2 9001 80\n" +
		"s Guard Running Valid Fast\n" +
		"p accept 80\n" +
		"r gotor2 " + B64(id2) + " " + B64(id2) + " 2020-01-01 00:00:00 10.0.0.3 9001 0\n" +
		"s Exit Running Valid Fast\n" +
		"directory-footer\n" +
		"directory-signature sha256 aabbcc ddee\n"
	relays, err := ParseConsensus(cons)
	if err != nil {
		t.Fatal(err)
	}
	if len(relays) != 2 {
		t.Fatalf("len %d", len(relays))
	}
	if relays[0].Nickname != "gotor1" || relays[0].DirPort != 80 || !relays[0].Has("Guard") || !relays[0].ExitAccept {
		t.Fatalf("%+v", relays[0])
	}
	if relays[1].Nickname != "gotor2" || !relays[1].Has("Exit") || relays[1].Has("Guard") {
		t.Fatalf("%+v", relays[1])
	}
}

func TestParseConsensusEmpty(t *testing.T) {
	relays, err := ParseConsensus("")
	if err != nil || len(relays) != 0 {
		t.Fatalf("%v %v", relays, err)
	}
}

func TestParseConsensusBadIdentity(t *testing.T) {
	if _, err := ParseConsensus("r nick !!!! aaaa 2020-01-01 00:00:00 10.0.0.2 9001 0\n"); err == nil {
		t.Fatal("expected identity error")
	}
}

func TestParseDescriptorsByFingerprint(t *testing.T) {
	var id [20]byte
	id[0] = 0xab
	relays := []*Relay{{Nickname: "other", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 9
	desc := "router ignored 10.0.0.2 9001 0 0\nfingerprint " + FingerprintHex(id) +
		"\nntor-onion-key " + B64(ntor) + "\naccept 80\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 9 || !relays[0].ExitAccept {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseConsensusSkipsOrphanSLine(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "s Guard Running\n" +
		"r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast Running Valid\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Fast") || relays[0].Has("Guard") {
		t.Fatalf("%+v %v", relays, err)
	}
}

func TestParseDescriptorsBadNtor(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	desc := "router gotor1 10.0.0.2 9001 0 0\nntor-onion-key " + B64(make([]byte, 20)) + "\n"
	if err := ParseDescriptors(desc, relays); err == nil {
		t.Fatal("expected ntor length error")
	}
}

func TestParseDescriptorsIgnoresOrphanKeys(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 7
	desc := "ntor-onion-key " + B64(ntor) + "\naccept *:*\nrouter gotor1 10.0.0.2 9001 0 0\nntor-onion-key " + B64(ntor) + "\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 7 || relays[0].ExitAccept {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseConsensusSkipsWhitespaceAndOrphanP(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "   \n" +
		"p accept 80\n" +
		"r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast Running\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Fast") || relays[0].ExitAccept {
		t.Fatalf("%+v %v", relays, err)
	}
}

func TestParseConsensusIgnoresMicrodescMLine(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast Guard\n" +
		"m abcdef0123456789abcdef0123456789abcdef01\n" +
		"v Tor 0.4.8.0\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Guard") {
		t.Fatalf("%+v %v", relays, err)
	}
}

func TestParseConsensusIgnoresTimestamps(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "network-status-version 3 flavor microdesc\n" +
		"vote-status consensus\n" +
		"consensus-method 32\n" +
		"voting-delay 300 300\n" +
		"package tor 0.4.8.0 https://dist.torproject.org/ sha256=aaaa\n" +
		"dir-source moria1 9695DFC35FFEB861329B9F1AB04C46397020CE31 128.31.0.39 9131 9101\n" +
		"valid-after 2020-01-01 00:00:00\n" +
		"fresh-until 2020-01-01 01:00:00\n" +
		"valid-until 2020-01-01 03:00:00\n" +
		"known-flags Authority BadExit Exit Fast Guard HSDir Running Stable V2Dir Valid\n" +
		"client-versions 0.4.8.0\n" +
		"server-versions 0.4.8.0,0.4.7.16\n" +
		"recommended-client-protocols Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=4-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1-2\n" +
		"recommended-relay-protocols Cons=1-2 Desc=1-2 DirCache=1-2 HSDir=1-2 HSIntro=3-5 HSRend=1-2 Link=4-5 LinkAuth=1,3 Microdesc=1-2 Relay=1-2 Padding=2 FlowCtrl=1-2\n" +
		"flag-thresholds stable-uptime=14400 stable-mtbf=15000 enough-mtbf=1 fast-speed=40960 guard-wfu=98.000% guard-tk=691200 guard-bw-inc-exits=102400 guard-bw-exc-exits=102400 enough-relays=1 ignoring-advertised-bws=0\n" +
		"r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast Running HSDir BadExit\n" +
		"bandwidth-weights Wbd=0 Wbe=0 Wbg=4143 Wbm=10000 Wdb=10000 Web=10000 Wed=10000 Wee=10000 Weg=10000 Wem=10000 Wgb=10000 Wgd=0 Wgg=5857 Wgm=5857 Wmb=10000 Wmd=0 Wme=0 Wmg=4143 Wmm=10000\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Running") || !relays[0].Has("HSDir") || !relays[0].Has("BadExit") {
		t.Fatalf("%+v %v", relays, err)
	}


}

func TestParseConsensusBadIP(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "r badip " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 not-an-ip 9001 0\n" +
		"s Fast\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || relays[0].Address != nil || relays[0].ORPort != 9001 {
		t.Fatalf("%+v %v", relays, err)
	}
}

func TestParseConsensusIgnoresParamsAndSharedRand(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "params circwindow=1000 CircuitPriorityHalflifeMsec=30000\n" +
		"shared-rand-previous-value 8 aa==\n" +
		"shared-rand-current-value 8 bb==\n" +
		"shared-rand-participate\n" +
		"r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 {
		t.Fatalf("%+v %v", relays, err)
	}
}






func TestParseDescriptorsSkipsBadMasterKey(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 4
	desc := "router gotor1 10.0.0.2 9001 0 0\nntor-onion-key " + B64(ntor) +
		"\nmaster-key-ed25519 !!!\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 4 || relays[0].Ed25519ID != nil {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseDescriptorsSkipsWhitespace(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 5
	desc := "   \nrouter gotor1 10.0.0.2 9001 0 0\nntor-onion-key " + B64(ntor) + "\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 5 {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseDescriptorsSkipsOrphanMasterKeyAndBareNtor(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 6
	ed := make([]byte, 32)
	ed[0] = 8
	desc := "master-key-ed25519 " + B64(ed) + "\nntor-onion-key\nrouter gotor1 10.0.0.2 9001 0 0\nntor-onion-key " + B64(ntor) + "\nmaster-key-ed25519\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 6 || relays[0].Ed25519ID != nil {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseConsensusPRejectAndIgnoredLines(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "network-status-version 3\n" +
		"r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"a [2001:db8::1]:9001\n" +
		"s Fast Running Exit Valid Stable V2Dir Foo\n" +
		"w Bandwidth=100 Unmeasured=1\n" +
		"p reject 1-65535\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Exit") || !relays[0].Has("V2Dir") || !relays[0].Has("Stable") || !relays[0].Has("Foo") || relays[0].ExitAccept {
		t.Fatalf("%+v %v", relays, err)
	}


}

func TestParseDescriptorsIgnoresOnionKeyAndReject(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 7
	desc := "router gotor1 10.0.0.2 9001 0 0\n" +
		"onion-key\n-----BEGIN RSA PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A\n-----END RSA PUBLIC KEY-----\n" +
		"ntor-onion-key " + B64(ntor) + "\n" +
		"reject *:*\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 7 || relays[0].ExitAccept {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseDescriptorsIgnoresPlatformContactBandwidth(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 9
	desc := "router gotor1 10.0.0.2 9001 0 0\n" +
		"platform Tor 0.4.8.0 on Linux\n" +
		"contact nobody@example.invalid\n" +
		"published 2020-01-01 00:00:00\n" +
		"bandwidth 1000 2000 3000\n" +
		"hibernating 1\n" +
		"ipv6-policy reject 1-65535\n" +
		"or-address [2001:db8::1]:9001\n" +
		"extra-info-digest ABCDEF0123456789ABCDEF0123456789ABCDEF01\n" +
		"opt fingerprint ABCDEF\n" +
		"tunnelled-dir-server\n" +
		"onion-key-crosscert\n-----BEGIN CROSSCERT-----\n-----END CROSSCERT-----\n" +
		"ntor-onion-key-crosscert 0\n-----BEGIN ED25519 CERT-----\n-----END ED25519 CERT-----\n" +
		"identity-ed25519\n-----BEGIN ED25519 CERT-----\n-----END ED25519 CERT-----\n" +
		"router-signature\n-----BEGIN SIGNATURE-----\n-----END SIGNATURE-----\n" +
		"proto Cons=1-2 Link=4-5 Relay=1-2\n" +
		"hidden-service-dir\n" +
		"caches-extra-info\n" +
		"family-cert\n-----BEGIN ED25519 CERT-----\n-----END ED25519 CERT-----\n" +
		"router-digest-sha256 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnop\n" +
		"ntor-onion-key " + B64(ntor) + "\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 9 {
		t.Fatalf("%+v", relays[0])
	}
}


func TestParseConsensusIPv6RLineAndIDEd25519(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "r gotor6 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 2001:db8::2 9001 80\n" +
		"id ed25519 " + B64(make([]byte, 32)) + "\n" +
		"s Fast Guard\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || relays[0].Nickname != "gotor6" {
		t.Fatalf("%+v %v", relays, err)
	}
	if relays[0].Address == nil || relays[0].Address.To16() == nil || relays[0].ORPort != 9001 || relays[0].DirPort != 80 {
		t.Fatalf("%+v", relays[0])
	}
}

func TestParseConsensusIgnoresPrProtoLine(t *testing.T) {
	id := make([]byte, 20)
	id[0] = 1
	cons := "r gotor1 " + B64(id) + " " + B64(id) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Fast Running\n" +
		"pr Cons=1-2 Desc=1-2 Link=4-5 Relay=1-2\n"
	relays, err := ParseConsensus(cons)
	if err != nil || len(relays) != 1 || !relays[0].Has("Fast") {
		t.Fatalf("%+v %v", relays, err)
	}
}


func TestParseDescriptorsIgnoresFamily(t *testing.T) {
	var id [20]byte
	id[0] = 1
	relays := []*Relay{{Nickname: "gotor1", Identity: id, Flags: map[string]bool{}}}
	ntor := make([]byte, 32)
	ntor[0] = 8
	desc := "router gotor1 10.0.0.2 9001 0 0\nfamily $ABCDEF\nntor-onion-key " + B64(ntor) + "\n"
	if err := ParseDescriptors(desc, relays); err != nil {
		t.Fatal(err)
	}
	if relays[0].NTorOnionKey[0] != 8 {
		t.Fatalf("%+v", relays[0])
	}
}








