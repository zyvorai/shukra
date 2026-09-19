package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Host paths FluxVM writes. Tests point these at a fixture; a missing file is
// not an error, so a host without FluxVM still scans QEMU.
var (
	fluxvmConfigFile   = "/etc/fluxvm.toml"
	fluxvmStateDefault = "/var/lib/fluxvm"
	fluxvmMetaRoot     = "/run/fluxvm/ebpf/vms"
)

// fluxVM is the slice of a FluxVM VmRecord this scan needs. The store is a
// map of UUID to record, with snake_case keys.
type fluxVM struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	PID     *int   `json:"pid"`
	TapName string `json:"tap_name"`
	Netns   string `json:"netns"`
}

func (r fluxVM) pid() int {
	if r.PID == nil || *r.PID <= 0 {
		return 0
	}
	return *r.PID
}

// enrichFluxVM names FluxVM guests from vms.json and points their taps at the
// host interface that carries guest frames. QEMU guests already found by the
// proc scan are updated in place. cloud-hypervisor, firecracker and
// fluxvm-hypervisor are added. A record with no live process is skipped.
func enrichFluxVM(procRoot string, vms []VM, hypervisor string) []VM {
	recs, err := readFluxVMs()
	if err != nil || len(recs) == 0 {
		return vms
	}
	byPID := make(map[int]int, len(vms))
	for i, vm := range vms {
		byPID[vm.PID] = i
	}
	for _, rec := range recs {
		pid := rec.pid()
		if pid == 0 {
			continue
		}
		dir := filepath.Join(procRoot, strconv.Itoa(pid))
		st, err := os.Stat(dir)
		if err != nil || !st.IsDir() {
			continue
		}
		taps := fluxvmIfaces(rec)
		if i, ok := byPID[pid]; ok {
			applyFluxVM(&vms[i], rec, taps)
			continue
		}
		if !isFluxVMM(dir) {
			continue
		}
		vm := vmFromDir(dir, pid, hypervisor)
		applyFluxVM(&vm, rec, taps)
		vms = append(vms, vm)
		byPID[pid] = len(vms) - 1
	}
	return vms
}

func applyFluxVM(vm *VM, rec fluxVM, taps []string) {
	vm.Runtime = "fluxvm"
	if rec.ID != "" {
		vm.UUID = rec.ID
	}
	switch {
	case rec.Name != "":
		vm.Name = rec.Name
	case vm.Name == "" || vm.Name == "qemu-unnamed":
		if rec.ID != "" {
			vm.Name = rec.ID
		}
	}
	if len(taps) > 0 {
		vm.Taps = taps
	}
}

// fluxvmIfaces is the host interface to trace, in order: the edge FluxVM's
// dataplane recorded, the host veth of a per-VM netns, or the tap name when
// that tap is already in the host namespace. The inner tap of a netns is never
// returned: it is not in the namespace this daemon can attach to.
func fluxvmIfaces(rec fluxVM) []string {
	if simple := uuidSimple(rec.ID); simple != "" {
		b, err := os.ReadFile(filepath.Join(fluxvmMetaRoot, simple, "iface"))
		if err == nil {
			if name := strings.TrimSpace(string(b)); name != "" {
				return []string{name}
			}
		}
	}
	if rec.Netns != "" {
		if short := shortID(rec.ID); short != "" {
			return []string{"vh" + short}
		}
	}
	if rec.TapName != "" {
		return []string{rec.TapName}
	}
	return nil
}

func uuidSimple(id string) string {
	return strings.ToLower(strings.ReplaceAll(strings.TrimSpace(id), "-", ""))
}

func shortID(id string) string {
	s := uuidSimple(id)
	if len(s) < 8 {
		return ""
	}
	return s[:8]
}

func isFluxVMM(dir string) bool {
	raw, err := os.ReadFile(filepath.Join(dir, "cmdline"))
	if err != nil {
		return false
	}
	args := SplitCmdline(raw)
	if len(args) == 0 {
		return false
	}
	switch strings.ToLower(filepath.Base(args[0])) {
	case "cloud-hypervisor", "firecracker", "fluxvm-hypervisor":
		return true
	default:
		return false
	}
}

func vmFromDir(dir string, pid int, hypervisor string) VM {
	vm := VM{PID: pid, Hypervisor: hypervisor}
	if raw, err := os.ReadFile(filepath.Join(dir, "cmdline")); err == nil {
		args := SplitCmdline(raw)
		vm.Cmdline = strings.Join(args, " ")
		vm.Comm = baseComm(args)
	}
	if comm, err := os.ReadFile(filepath.Join(dir, "comm")); err == nil {
		if c := strings.TrimSpace(string(comm)); c != "" {
			vm.Comm = c
		}
	}
	vm.Threads, vm.ThreadInfo = threads(dir, pid)
	return vm
}

func readFluxVMs() ([]fluxVM, error) {
	b, err := os.ReadFile(filepath.Join(fluxvmStateDir(), "vms.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	if strings.TrimSpace(string(b)) == "" {
		return nil, nil
	}
	var raw map[string]fluxVM
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, err
	}
	out := make([]fluxVM, 0, len(raw))
	for key, rec := range raw {
		if rec.ID == "" {
			rec.ID = key
		}
		out = append(out, rec)
	}
	return out, nil
}

func fluxvmStateDir() string {
	b, err := os.ReadFile(fluxvmConfigFile)
	if err == nil {
		if dir := parseStateDir(string(b)); dir != "" {
			return dir
		}
	}
	return fluxvmStateDefault
}

func parseStateDir(s string) string {
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) != "state_dir" {
			continue
		}
		return tomlString(v)
	}
	return ""
}

func tomlString(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if v[0] == '"' || v[0] == '\'' {
		q := v[0]
		v = v[1:]
		if i := strings.IndexByte(v, q); i >= 0 {
			return v[:i]
		}
		return ""
	}
	if i := strings.IndexAny(v, " \t#"); i >= 0 {
		v = v[:i]
	}
	return v
}
