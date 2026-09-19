// Package identity resolves KVM guests from the QEMU process command line.
// It does not see processes inside the guest.
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
	Cmdline    string   `json:"cmdline,omitempty"`
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

// Scan walks a /proc-shaped directory and returns QEMU virtual machines.
// A missing root yields an empty list, not an error, so shukrad can still serve.
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
		vm.Threads = threads(dir, pid)
		out = append(out, vm)
	}
	return out, nil
}

func threads(dir string, pid int) []int {
	task := filepath.Join(dir, "task")
	entries, err := os.ReadDir(task)
	if err != nil {
		return []int{pid}
	}
	var ids []int
	for _, ent := range entries {
		id, err := strconv.Atoi(ent.Name())
		if err != nil || id <= 0 {
			continue
		}
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return []int{pid}
	}
	return ids
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
