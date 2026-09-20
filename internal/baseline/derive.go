package baseline

import (
	"net/netip"
	"strings"
)

// Prefix is the network an address belongs to for the purpose of "new for this VM": the /24 of an IPv4 address
// and the /64 of an IPv6 address. A whole network and not the address, so a service that moves between
// neighbouring addresses, or a client that lands on a different member of a pool, is not new every time. It is
// "" for something that is not an address.
func Prefix(addr string) string {
	a, err := netip.ParseAddr(strings.TrimSpace(addr))
	if err != nil {
		return ""
	}
	a = a.Unmap()
	bits := 64
	if a.Is4() {
		bits = 24
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return ""
	}
	return p.String()
}

// twoLabelSuffixes are public suffixes of two labels, so the registrable name has three. It is short on
// purpose: it covers the ones seen in practice, and a name under a suffix it lacks is learned one label too
// wide (foo.example.co.xx is "co.xx"), which only makes it quieter, never louder.
var twoLabelSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true, "me.uk": true, "ltd.uk": true, "plc.uk": true, "net.uk": true, "sch.uk": true,
	"com.au": true, "net.au": true, "org.au": true, "edu.au": true, "gov.au": true,
	"co.nz": true, "org.nz": true, "govt.nz": true, "ac.nz": true, "net.nz": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true, "go.jp": true,
	"co.kr": true, "or.kr": true, "go.kr": true, "ac.kr": true,
	"com.br": true, "net.br": true, "org.br": true, "gov.br": true,
	"com.cn": true, "net.cn": true, "org.cn": true, "gov.cn": true, "edu.cn": true,
	"com.hk": true, "org.hk": true, "com.sg": true, "edu.sg": true, "com.tw": true, "org.tw": true,
	"com.mx": true, "com.ar": true, "com.co": true, "com.pe": true, "com.tr": true, "com.ua": true,
	"co.in": true, "net.in": true, "org.in": true, "ac.in": true, "gov.in": true, "co.id": true, "co.th": true,
	"co.za": true, "org.za": true, "co.il": true, "org.il": true, "com.eg": true, "com.ng": true, "co.ke": true,
}

// Registrable is the part of a DNS name a person would call the site: "www.api.example.com" is "example.com",
// and "shop.example.co.uk" is "example.co.uk". The name is lower-cased and a trailing dot is ignored. Reverse
// lookups collapse to "in-addr.arpa" and "ip6.arpa", because every address has a different one and they say
// nothing about what the guest is doing. A name with one label (a host on the local network) is itself.
func Registrable(name string) string {
	name = strings.Trim(strings.ToLower(strings.TrimSpace(name)), ".")
	if name == "" || name == "." {
		return ""
	}
	labels := strings.Split(name, ".")
	n := len(labels)
	if n >= 2 && labels[n-1] == "arpa" {
		switch labels[n-2] {
		case "in-addr":
			return "in-addr.arpa"
		case "ip6":
			return "ip6.arpa"
		}
	}
	if n == 1 {
		return name
	}
	keep := 2
	if n >= 3 && twoLabelSuffixes[strings.Join(labels[n-2:], ".")] {
		keep = 3
	}
	return strings.Join(labels[n-keep:], ".")
}
