package directory

import "testing"

func TestParseConsensusAndDescriptors(t *testing.T) {
	ident := make([]byte, 20)
	ident[0] = 1
	ntor := make([]byte, 32)
	ntor[0] = 2
	ed := make([]byte, 32)
	ed[0] = 3
	cons := "network-status-version 3\nvote-status consensus\n" +
		"r gotor1 " + B64(ident) + " " + B64(ident) + " 2020-01-01 00:00:00 10.0.0.2 9001 0\n" +
		"s Guard Running Valid Fast\n" +
		"directory-footer\n"
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
