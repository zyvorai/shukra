package baseline

import "testing"

func TestPrefixIsTheSlash24OfAnIPv4AndTheSlash64OfAnIPv6(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":          "203.0.113.0/24",
		"203.0.113.250":        "203.0.113.0/24",
		"10.0.7.1":             "10.0.7.0/24",
		"2001:db8:1:2:3:4:5:6": "2001:db8:1:2::/64",
		"fd00::1":              "fd00::/64",
		"::ffff:198.51.100.7":  "198.51.100.0/24", // an IPv4 carried in IPv6 is the IPv4
		" 192.168.122.5 ":      "192.168.122.0/24",
		"":                     "",
		"not an address":       "",
		"203.0.113.9/24":       "",
		"203.0.113":            "",
	} {
		if got := Prefix(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}

func TestRegistrableIsTheSiteNotTheHost(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":              "example.com",
		"www.example.com":          "example.com",
		"a.b.c.example.com":        "example.com",
		"WWW.Example.COM.":         "example.com", // case and the root dot
		"shop.example.co.uk":       "example.co.uk",
		"example.co.uk":            "example.co.uk",
		"co.uk":                    "co.uk", // a suffix on its own is all there is
		"api.example.com.au":       "example.com.au",
		"deep.host.example.co.jp":  "example.co.jp",
		"printer":                  "printer", // one label: a host on the local network
		"localhost":                "localhost",
		"4.3.2.1.in-addr.arpa":     "in-addr.arpa",
		"8.b.d.0.1.0.0.2.ip6.arpa": "ip6.arpa",
		"foo.example.co.xx":        "co.xx", // a suffix this list lacks: one label too wide, quieter and not louder
		"":                         "",
		".":                        "",
		"  ":                       "",
	} {
		if got := Registrable(in); got != want {
			t.Errorf("%q: %q, want %q", in, got, want)
		}
	}
}
