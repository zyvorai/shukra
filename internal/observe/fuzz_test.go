package observe

import "testing"

func FuzzDecodeDNS(f *testing.F) {
	f.Add(make([]byte, dnsEventSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		decodeDNS(b, func(uint32) string { return "tap0" })
	})
}

func FuzzDecodeTLS(f *testing.F) {
	f.Add(make([]byte, tlsEventSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		decodeTLS(b, func(uint32) string { return "tap0" })
	})
}

func FuzzDecodeRing(f *testing.F) {
	f.Add(make([]byte, ringEventSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		DecodeRing(b)
	})
}

func FuzzDecodeVMM(f *testing.F) {
	f.Add(make([]byte, vmmEventSize))
	f.Fuzz(func(t *testing.T, b []byte) {
		decodeVMM(b, func(uint32) string { return "" })
	})
}
