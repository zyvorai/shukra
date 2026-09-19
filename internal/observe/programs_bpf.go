//go:build shukrabpf && linux

package observe

import (
	"fmt"
	"sync"

	"github.com/zyvorai/shukra/internal/bpfgen"
)

var (
	loadOnce sync.Once
	loaded   []Program
)

func programs() []Program {
	loadOnce.Do(func() {
		got, err := bpfgen.Attach()
		if err != nil {
			detail := err.Error()
			loaded = []Program{
				{Name: "kvm", Status: "detached", Detail: detail},
				{Name: "sched", Status: "detached", Detail: detail},
				{Name: "block", Status: "detached", Detail: detail},
				{Name: "net", Status: "detached", Detail: detail},
			}
			return
		}
		loaded = make([]Program, 0, len(got))
		for _, p := range got {
			loaded = append(loaded, Program{Name: p.Name, Status: p.Status, Detail: p.Detail})
		}
	})
	out := append([]Program(nil), loaded...)
	if n := lostSamples(); n > 0 {
		suffix := fmt.Sprintf("lost=%d", n)
		for i := range out {
			switch out[i].Name {
			case "sched", "block", "net":
				if out[i].Detail == "" {
					out[i].Detail = suffix
				} else {
					out[i].Detail += "; " + suffix
				}
			}
		}
	}
	return out
}
