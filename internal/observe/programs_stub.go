//go:build !shukrabpf

package observe

func programs() []Program {
	detail := "CO-RE objects are not linked in this binary. On Linux: make generate && go build -tags shukrabpf. No counters were invented."
	return []Program{
		{Name: "kvm", Status: "detached", Detail: detail},
		{Name: "sched", Status: "detached", Detail: detail},
		{Name: "block", Status: "detached", Detail: detail},
		{Name: "net", Status: "detached", Detail: detail},
		{Name: "tap", Status: "detached", Detail: detail},
	}
}
