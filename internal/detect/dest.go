// Package detect matches destination IPs against an operator watchlist.
// Matching is a userspace decision. It does not attach a datapath program.
package detect

import (
	"fmt"
	"net"

	"gopkg.in/yaml.v3"
)

// Rule is one destination the operator asked to notice.
type Rule struct {
	CIDR     string `json:"cidr" yaml:"cidr"`
	Severity string `json:"severity" yaml:"severity"`
	Name     string `json:"name" yaml:"name"`
}

type file struct {
	Destinations []Rule `yaml:"destinations"`
}

// Watchlist is a parsed destination set.
type Watchlist struct {
	rules []compiled
}

type compiled struct {
	rule Rule
	net  *net.IPNet
}

// ParseYAML loads the watchlist. An empty document is an empty list, not an error.
func ParseYAML(b []byte) (*Watchlist, error) {
	var f file
	if len(b) == 0 {
		return &Watchlist{}, nil
	}
	if err := yaml.Unmarshal(b, &f); err != nil {
		return nil, err
	}
	w := &Watchlist{}
	for _, r := range f.Destinations {
		if r.CIDR == "" {
			return nil, fmt.Errorf("destination %q has empty cidr", r.Name)
		}
		_, n, err := net.ParseCIDR(r.CIDR)
		if err != nil {
			ip := net.ParseIP(r.CIDR)
			if ip == nil {
				return nil, fmt.Errorf("destination %q: %w", r.Name, err)
			}
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			n = &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}
		}
		if r.Severity == "" {
			r.Severity = "high"
		}
		w.rules = append(w.rules, compiled{rule: r, net: n})
	}
	return w, nil
}

// Match returns the first rule that contains ip.
func (w *Watchlist) Match(ip net.IP) (Rule, bool) {
	if w == nil || ip == nil {
		return Rule{}, false
	}
	for _, r := range w.rules {
		if r.net.Contains(ip) {
			return r.rule, true
		}
	}
	return Rule{}, false
}
