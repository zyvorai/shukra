//go:build shukrabpf && linux

package observe

import (
	"sync"

	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/shukra/internal/bpfgen"
	"github.com/zyvorai/shukra/internal/event"
)

var vmmStartOnce sync.Once

// DisableVMM keeps the VMM tripwire program from being loaded (shukrad -vmm-tripwires=false). It must be called
// before the programs are attached. The reason starts with "turned off with ", which the doctor reads as a choice
// and not a fault (state.switchedOff).
func DisableVMM() { bpfgen.Disable("vmm", "turned off with -vmm-tripwires=false") }

// StartVMM reads the VMM tripwire ring: the files a VMM process (or something it started) opens, and the calls it
// has no business making. A record that does not decode is counted as lost, never guessed at.
func StartVMM(handler func(event.Event)) {
	vmmStartOnce.Do(func() {
		if handler == nil {
			return
		}
		for _, live := range bpfgen.Collections() {
			if live.Coll == nil || live.Name != "vmm" {
				continue
			}
			m := live.Coll.Maps["vmm_events"]
			if m == nil {
				continue
			}
			rd, err := ringbuf.NewReader(m)
			if err != nil {
				lost.Add(1)
				return
			}
			readTapRing(rd, handler, decodeVMM)
		}
	})
}
