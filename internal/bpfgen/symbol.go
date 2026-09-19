package bpfgen

import "strings"

// symbolText is the function name the kernel wrote into a fixed buffer: up to the first NUL, and
// nothing when it wrote nothing or something that is not a name.
func symbolText(b []byte) string {
	for i, c := range b {
		if c == 0 {
			b = b[:i]
			break
		}
	}
	s := strings.TrimSpace(string(b))
	for _, r := range s {
		if r < 0x21 || r > 0x7e {
			return ""
		}
	}
	return s
}
