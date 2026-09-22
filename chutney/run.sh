#!/bin/sh
# Opt-in C-Tor testing network: 1 dirauth + 1 middle + 1 exit.
set -eu
IP="${CHUTNEY_IP:-172.28.0.50}"
BASE=/var/lib/tor-net
DUMMY="DirAuthority dummy orport=1 no-v2 v3ident=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA 127.0.0.1:1 AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

mkdir -p "$BASE/g/keys" "$BASE/m/keys" "$BASE/e/keys"

COMMON="
TestingTorNetwork 1
AssumeReachable 1
AuthDirTestReachability 0
TestingAuthDirTimeToLearnReachability 0
TestingDirAuthVoteGuard *
TestingMinExitFlagThreshold 0
ExitPolicyRejectPrivate 0
ExitPolicyRejectLocalInterfaces 0
ExtendAllowPrivateAddresses 1
EnforceDistinctSubnets 0
V3AuthVotingInterval 20
V3AuthVoteDelay 4
V3AuthDistDelay 4
TestingV3AuthInitialVotingInterval 20
TestingV3AuthInitialVoteDelay 4
TestingV3AuthInitialDistDelay 4
ProtocolWarnings 1
SafeLogging 0
Log notice stdout
DisableDebuggerAttachment 0
PublishServerDescriptor 1
FetchDirInfoEarly 1
FetchDirInfoExtraEarly 1
SocksPort 0
ControlPort 0
"

gen_relay() {
	nick="$1"
	dd="$2"
	dirport="$3"
	auth="$4"
	extra=""
	if [ "$auth" = "1" ]; then
		extra="AuthoritativeDirectory 1
V3AuthoritativeDirectory 1
ContactInfo none@example.invalid"
	fi
	dp="DirPort 0"
	if [ "$dirport" != "0" ]; then
		dp="DirPort $dirport"
	fi
	cat >"$dd/torrc.gen" <<EOF
$COMMON
$DUMMY
Nickname $nick
DataDirectory $dd
Address 127.0.0.1
ORPort 1
$dp
$extra
DisableNetwork 1
EOF
	tor --defaults-torrc /dev/null -f "$dd/torrc.gen" --list-fingerprint >/dev/null
}

printf '\n' | tor-gencert --create-identity-key -m 12 -a "${IP}:7000" --passphrase-fd 0 \
	-i "$BASE/g/keys/authority_identity_key" \
	-s "$BASE/g/keys/authority_signing_key" \
	-c "$BASE/g/keys/authority_certificate"

gen_relay g "$BASE/g" 2 1
gen_relay m "$BASE/m" 0 0
gen_relay e "$BASE/e" 0 0

GFP=$(awk '{print $2}' "$BASE/g/fingerprint")
V3=$(awk '/^fingerprint /{print $2}' "$BASE/g/keys/authority_certificate")
DA="DirAuthority g orport=5000 no-v2 v3ident=${V3} ${IP}:7000 ${GFP}"

write_rc() {
	nick="$1"
	dd="$2"
	orport="$3"
	dirport="$4"
	role="$5"
	addr="$6"
	auth=""
	exitpol="ExitRelay 0
ExitPolicy reject *:*"
	if [ "$role" = "auth" ]; then
		auth="AuthoritativeDirectory 1
V3AuthoritativeDirectory 1
ContactInfo none@example.invalid"
	fi
	if [ "$role" = "exit" ]; then
		exitpol="ExitRelay 1
ExitPolicy accept *:*"
	fi
	dirline="DirPort 0"
	if [ "$dirport" != "0" ]; then
		dirline="DirPort ${dirport}"
	fi
	cat >"$dd/torrc" <<EOF
$COMMON
$DA
Nickname $nick
DataDirectory $dd
Address $addr
ORPort $orport
$dirline
$auth
$exitpol
EOF
}

write_rc g "$BASE/g" 5000 7000 auth "$IP"
write_rc m "$BASE/m" 5001 0 middle "$IP"
write_rc e "$BASE/e" 5002 0 exit "$IP"

tor --defaults-torrc /dev/null -f "$BASE/g/torrc" &
tor --defaults-torrc /dev/null -f "$BASE/m/torrc" &
tor --defaults-torrc /dev/null -f "$BASE/e/torrc" &
wait
