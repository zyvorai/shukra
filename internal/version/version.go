// Package version is the Shukra release identity.
package version

const (
	Product = "shukra"
	Tagline = "eBPF-powered runtime intelligence and security for KVM"
)

// Version is stamped at build time:
//
//	go build -ldflags "-X github.com/zyvorai/shukra/internal/version.Version=v1.2.3"
//
// A plain `go build` reports the development default below.
var Version = "0.1.0"
