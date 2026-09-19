// Package identity resolves KVM guests from the QEMU process command line and,
// when FluxVM is installed, from its VM records. It does not see processes
// inside the guest.
package identity

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// VM is one QEMU process and the threads in its thread group.
type VM struct {
	Name       string   `json:"name"`
	UUID       string   `json:"uuid,omitempty"`
	Runtime    string   `json:"runtime"`
	Hypervisor string   `json:"hypervisor,omitempty"`
	PID        int      `json:"pid"`
	Comm       string   `json:"comm,omitempty"`
	Taps       []string `json:"taps,omitempty"`
	Threads    []int    `json:"threads,omitempty"`
	ThreadInfo []Thread `json:"threadInfo,omitempty"`
	Cmdline    string   `json:"cmdline,omitempty"`
}

// Thread is one QEMU task and the role inferred from its comm.
type Thread struct {
	TID  int    `json:"tid"`
	Comm string `json:"comm,omitempty"`
	Role string `json:"role"`
}

// SplitCmdline splits a /proc/<pid>/cmdline buffer on NUL.
func SplitCmdline(b []byte) []string {
	parts := bytes.Split(b, []byte{0})
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if len(p) == 0 {
			continue
		}
		out = append(out, string(p))
	}
	return out
}

// ParseCmdline extracts name, UUID, tap ifnames, and runtime from a QEMU argv.
// ok is false when the argv is not a QEMU system emulator.
func ParseCmdline(args []string) (VM, bool) {
	if !isQEMU(args) {
		return VM{}, false
	}
	vm := VM{Runtime: "qemu", Comm: baseComm(args)}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-name" && i+1 < len(args):
			i++
			vm.Name = parseName(args[i])
		case strings.HasPrefix(a, "-name="):
			vm.Name = parseName(strings.TrimPrefix(a, "-name="))
		case a == "-uuid" && i+1 < len(args):
			i++
			vm.UUID = args[i]
		case strings.HasPrefix(a, "-uuid="):
			vm.UUID = strings.TrimPrefix(a, "-uuid=")
		}
		if name := ifname(a); name != "" {
			vm.Taps = append(vm.Taps, name)
		}
	}
	joined := strings.Join(args, " ")
	vm.Runtime = runtimeOf(joined, vm.Name)
	vm.Cmdline = joined
	if vm.Name == "" {
		vm.Name = "qemu-unnamed"
	}
	return vm, true
}

func isQEMU(args []string) bool {
	if len(args) == 0 {
		return false
	}
	base := strings.ToLower(filepath.Base(args[0]))
	return strings.HasPrefix(base, "qemu-system")
}

func baseComm(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return filepath.Base(args[0])
}

func parseName(token string) string {
	token = strings.TrimSpace(token)
	if token == "" {
		return ""
	}
	if strings.Contains(token, "guest=") {
		rest := token[strings.Index(token, "guest=")+len("guest="):]
		if i := strings.IndexByte(rest, ','); i >= 0 {
			rest = rest[:i]
		}
		return rest
	}
	if i := strings.IndexByte(token, ','); i >= 0 {
		token = token[:i]
	}
	return token
}

func ifname(arg string) string {
	const key = "ifname="
	i := strings.Index(arg, key)
	if i < 0 {
		return ""
	}
	rest := arg[i+len(key):]
	if j := strings.IndexAny(rest, ", \t"); j >= 0 {
		rest = rest[:j]
	}
	return rest
}

func runtimeOf(cmdline, name string) string {
	low := strings.ToLower(cmdline + " " + name)
	if strings.Contains(low, "kubevirt") || strings.Contains(low, "virt-launcher") {
		return "kubevirt"
	}
	if strings.Contains(low, "libvirt") {
		return "libvirt"
	}
	return "qemu"
}

// Scan walks a /proc-shaped directory and returns virtual machines: QEMU from
// the command line, and FluxVM guests of any backend from vms.json. A missing
// root yields an empty list, not an error, so shukrad can still serve.
func Scan(root, hypervisor string) ([]VM, error) {
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []VM
	for _, ent := range entries {
		if !ent.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(ent.Name())
		if err != nil || pid <= 0 {
			continue
		}
		dir := filepath.Join(root, ent.Name())
		raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
		if err != nil {
			continue
		}
		args := SplitCmdline(raw)
		vm, ok := ParseCmdline(args)
		if !ok {
			continue
		}
		if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
			vm.Comm = strings.TrimSpace(string(comm))
		}
		vm.PID = pid
		vm.Hypervisor = hypervisor
		vm.Threads, vm.ThreadInfo = threads(dir, pid)
		vm.Taps = mergeNames(vm.Taps, tunTaps(dir))
		out = append(out, vm)
	}
	return enrichFluxVM(root, out, hypervisor), nil
}

func threads(dir string, pid int) ([]int, []Thread) {
	task := filepath.Join(dir, "task")
	entries, err := os.ReadDir(task)
	if err != nil {
		return []int{pid}, []Thread{{TID: pid, Role: "other"}}
	}
	var ids []int
	var info []Thread
	for _, ent := range entries {
		id, err := strconv.Atoi(ent.Name())
		if err != nil || id <= 0 {
			continue
		}
		ids = append(ids, id)
		comm := ""
		if b, err := os.ReadFile(filepath.Join(task, ent.Name(), "comm")); err == nil {
			comm = strings.TrimSpace(string(b))
		}
		info = append(info, Thread{TID: id, Comm: comm, Role: Role(comm)})
	}
	if len(ids) == 0 {
		return []int{pid}, []Thread{{TID: pid, Role: "other"}}
	}
	return ids, info
}

// Role labels a QEMU task comm. It is not an in-guest process.
func Role(comm string) string {
	c := strings.TrimSpace(comm)
	low := strings.ToLower(c)
	switch {
	case strings.HasPrefix(c, "CPU") || strings.Contains(low, "kvm"):
		return "vcpu"
	case strings.HasPrefix(c, "IO") || strings.Contains(low, "iothread"):
		return "iothread"
	case strings.Contains(low, "vhost"):
		return "vhost"
	default:
		return "other"
	}
}

// Owns reports whether pid is the QEMU process or one of its threads.
func (vm VM) Owns(pid uint32) bool {
	if pid == 0 {
		return false
	}
	if int(pid) == vm.PID {
		return true
	}
	for _, t := range vm.Threads {
		if int(pid) == t {
			return true
		}
	}
	return false
}

// tunTaps finds the tap interfaces a QEMU process holds open. libvirt gives QEMU
// its taps as file descriptors (-netdev tap,fd=37), so their names are not on the
// command line. The kernel does name each one in the tun fd's fdinfo, as "iff:".
//
// Reading another user's fd and fdinfo directories needs the daemon to be root
// with CAP_DAC_READ_SEARCH and CAP_SYS_PTRACE. When it cannot read them the
// result is empty, and the VM keeps whatever taps its command line named: a VM
// with no known tap is never invented one.
func tunTaps(dir string) []string {
	fds, err := os.ReadDir(filepath.Join(dir, "fd"))
	if err != nil {
		return nil
	}
	var names []string
	for _, fd := range fds {
		target, err := os.Readlink(filepath.Join(dir, "fd", fd.Name()))
		if err != nil || target != "/dev/net/tun" {
			continue
		}
		info, err := os.ReadFile(filepath.Join(dir, "fdinfo", fd.Name()))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(info), "\n") {
			if k, v, ok := strings.Cut(line, ":"); ok && k == "iff" {
				if name := strings.TrimSpace(v); name != "" {
					names = append(names, name)
				}
			}
		}
	}
	return names
}

// mergeNames appends the names in extra that are not already in base, keeping order.
func mergeNames(base, extra []string) []string {
	seen := make(map[string]bool, len(base))
	for _, n := range base {
		seen[n] = true
	}
	for _, n := range extra {
		if !seen[n] {
			seen[n] = true
			base = append(base, n)
		}
	}
	return base
}
