// Package observe reports eBPF program state.
// The default build does not link CO-RE objects. `make generate` on Linux
// with clang and BTF produces them; pass -tags shukrabpf to load them.
package observe

// Program is the attach state the API shows.
type Program struct {
	Name   string
	Status string
	Detail string
}

// Programs returns the four observation programs. In this build they are detached
// unless the binary was linked with -tags shukrabpf.
func Programs() []Program {
	return programs()
}
