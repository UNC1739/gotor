package directory

// V3Authorities are the current Tor v3 directory authorities
// (C-Tor src/app/config/auth_dirs.inc). DirAddr is IPv4:DirPort.
var V3Authorities = []Authority{
	{Nickname: "moria1", V3Ident: "F533C81CEF0BC0267857C99B2F471ADF249FA232", DirAddr: "128.31.0.39:9231"},
	{Nickname: "tor26", V3Ident: "2F3DF9CA0E5D36F2685A2DA67184EB8DCB8CBA8C", DirAddr: "217.196.147.77:80"},
	{Nickname: "dizum", V3Ident: "E8A9C45EDE6D711294FADF8E7951F4DE6CA56B58", DirAddr: "45.66.35.11:80"},
	{Nickname: "gabelmoo", V3Ident: "ED03BB616EB2F60BEC80151114BB25CEF515B226", DirAddr: "131.188.40.189:80"},
	{Nickname: "dannenberg", V3Ident: "0232AF901C31A04EE9848595AF9BB7620D4C5B2E", DirAddr: "193.23.244.244:80"},
	{Nickname: "maatuska", V3Ident: "49015F787433103580E3B66A1707A00E60F2D15B", DirAddr: "171.25.193.9:443"},
	{Nickname: "longclaw", V3Ident: "23D15D965BC35114467363C165C4F724B64B4F66", DirAddr: "199.58.81.140:80"},
	{Nickname: "bastet", V3Ident: "27102BC123E7AF1D4741AE047E160C91ADC76B21", DirAddr: "204.13.164.118:80"},
	{Nickname: "faravahar", V3Ident: "70849B868D606BAECFB6128C5E3D782029AA394F", DirAddr: "216.218.219.41:80"},
}

type Authority struct {
	Nickname string
	V3Ident  string
	DirAddr  string
}

func Quorum(n int) int {
	if n <= 0 {
		return 1
	}
	return n/2 + 1
}
