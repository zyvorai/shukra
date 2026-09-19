//go:build !shukrabpf

package observe

// DropSample has nothing to read in a build without BPF.
func DropSample() []DropCounters { return nil }
