package identity

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func TestFluxVMScan(t *testing.T) {
	proc := t.TempDir()
	state := t.TempDir()
	meta := t.TempDir()
	restoreFluxVMPaths(t, filepath.Join(t.TempDir(), "absent.toml"), state, meta)

	const (
		netnsID  = "075a3816-1111-2222-3333-444455556666"
		bridgeID = "aabbccdd-1111-2222-3333-444455556666"
		chID     = "11111111-2222-3333-4444-555555555555"
		fcID     = "22222222-3333-4444-5555-666666666666"
		hvID     = "33333333-4444-5555-6666-777777777777"
		directID = "44444444-5555-6666-7777-888888888888"
	)
	writeProc(t, proc, 101, "qemu-system-x86_64\x00-netdev\x00tap,id=net0,ifname=tap075a3816,script=no\x00", "qemu-system-x86_64")
	writeProc(t, proc, 102, "qemu-system-x86_64\x00-netdev\x00tap,id=net0,ifname=tapOLD,script=no\x00", "qemu-system-x86_64")
	writeProc(t, proc, 201, "cloud-hypervisor\x00--api-socket\x00/run/ch.sock\x00--net\x00tap=tap11111111\x00", "cloud-hypervis")
	writeProc(t, proc, 202, "firecracker\x00--api-sock\x00/run/firecracker.socket\x00--config-file\x00/config.json\x00", "firecracker")
	writeProc(t, proc, 203, "fluxvm-hypervisor\x00--api-sock\x00/run/fluxvm.sock\x00--boot-config\x00/boot.json\x00", "fluxvm-hypervis")
	writeProc(t, proc, 204, "cloud-hypervisor\x00--net\x00tap=inner\x00", "cloud-hypervis")
	writeProc(t, proc, 301, "qemu-system-x86_64\x00-name\x00guest=libvirt-db\x00-pidfile\x00/var/run/libvirt/qemu/libvirt-db.pid\x00-netdev\x00tap,id=n0,ifname=taplib,script=no\x00", "qemu-system-x86_64")

	recs := map[string]fluxVM{
		netnsID:      {ID: netnsID, Name: "netns-guest", PID: intPtr(101), TapName: "tap075a3816", Netns: "eph-075a3816"},
		bridgeID:     {ID: bridgeID, Name: "bridge-guest", PID: intPtr(102), TapName: "ephaabbccdd"},
		chID:         {ID: chID, Name: "ch-guest", PID: intPtr(201), Netns: "eph-11111111"},
		fcID:         {ID: fcID, Name: "fc-guest", PID: intPtr(202), Netns: "eph-22222222"},
		hvID:         {ID: hvID, Name: "hv-guest", PID: intPtr(203), Netns: "eph-33333333"},
		directID:     {ID: directID, Name: "direct-guest", PID: intPtr(204), TapName: "inner", Netns: "eph-44444444"},
		"stopped-id": {ID: "55555555-6666-7777-8888-999999999999", Name: "stopped", TapName: "ephstopped"},
		"dead-id":    {ID: "66666666-7777-8888-9999-aaaaaaaaaaaa", Name: "gone", PID: intPtr(99999), TapName: "ephgone"},
	}
	raw, err := json.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "vms.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	simple := uuidSimple(directID)
	if err := os.MkdirAll(filepath.Join(meta, simple), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(meta, simple, "iface"), []byte("vh-direct\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	vms, err := Scan(proc, "host")
	if err != nil {
		t.Fatal(err)
	}
	byPID := map[int]VM{}
	for _, vm := range vms {
		byPID[vm.PID] = vm
	}
	if len(byPID) != 7 {
		t.Fatalf("got %d VMs, want 7 (stopped and dead omitted): %+v", len(byPID), vms)
	}

	netns := byPID[101]
	if netns.Name != "netns-guest" || netns.UUID != netnsID || netns.Runtime != "fluxvm" || netns.Hypervisor != "host" {
		t.Fatalf("netns guest: %+v", netns)
	}
	if len(netns.Taps) != 1 || netns.Taps[0] != "vh075a3816" {
		t.Fatalf("netns taps %v, want [vh075a3816]", netns.Taps)
	}

	bridge := byPID[102]
	if bridge.Name != "bridge-guest" || bridge.Runtime != "fluxvm" || len(bridge.Taps) != 1 || bridge.Taps[0] != "ephaabbccdd" {
		t.Fatalf("bridge guest: %+v", bridge)
	}

	for _, c := range []struct {
		pid  int
		name string
		tap  string
	}{
		{201, "ch-guest", "vh11111111"},
		{202, "fc-guest", "vh22222222"},
		{203, "hv-guest", "vh33333333"},
	} {
		vm := byPID[c.pid]
		if vm.Name != c.name || vm.Runtime != "fluxvm" || len(vm.Taps) != 1 || vm.Taps[0] != c.tap {
			t.Fatalf("pid %d: %+v", c.pid, vm)
		}
		if len(vm.Threads) == 0 || vm.Threads[0] != c.pid {
			t.Fatalf("pid %d threads %v", c.pid, vm.Threads)
		}
	}

	direct := byPID[204]
	if direct.Runtime != "fluxvm" || len(direct.Taps) != 1 || direct.Taps[0] != "vh-direct" {
		t.Fatalf("direct guest should use the recorded host iface, got %+v", direct)
	}

	lib := byPID[301]
	if lib.Name != "libvirt-db" || lib.Runtime != "libvirt" || lib.UUID != "" || len(lib.Taps) != 1 || lib.Taps[0] != "taplib" {
		t.Fatalf("libvirt guest was changed: %+v", lib)
	}
	for _, name := range []string{"stopped", "gone"} {
		for _, vm := range vms {
			if vm.Name == name {
				t.Fatalf("record %s should be ignored: %+v", name, vm)
			}
		}
	}
}

func TestFluxVMStateDirFromConfig(t *testing.T) {
	proc := t.TempDir()
	state := t.TempDir()
	cfg := filepath.Join(t.TempDir(), "fluxvm.toml")
	if err := os.WriteFile(cfg, []byte("# state_dir = \"/ignored\"\nstate_dir = \""+state+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	restoreFluxVMPaths(t, cfg, t.TempDir(), t.TempDir())
	writeProc(t, proc, 7, "firecracker\x00--config-file\x00/config.json\x00", "firecracker")
	id := "abcdef01-0000-0000-0000-000000000000"
	raw, err := json.Marshal(map[string]fluxVM{
		id: {Name: "from-toml", PID: intPtr(7), Netns: "eph-abcdef01"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, "vms.json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	vms, err := Scan(proc, "h")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || vms[0].Name != "from-toml" || vms[0].UUID != id || len(vms[0].Taps) != 1 || vms[0].Taps[0] != "vhabcdef01" {
		t.Fatalf("%+v", vms)
	}
}

func restoreFluxVMPaths(t *testing.T, config, state, meta string) {
	t.Helper()
	prevC, prevS, prevM := fluxvmConfigFile, fluxvmStateDefault, fluxvmMetaRoot
	fluxvmConfigFile, fluxvmStateDefault, fluxvmMetaRoot = config, state, meta
	t.Cleanup(func() {
		fluxvmConfigFile, fluxvmStateDefault, fluxvmMetaRoot = prevC, prevS, prevM
	})
}

func writeProc(t *testing.T, root string, pid int, cmdline, comm string) {
	t.Helper()
	id := strconv.Itoa(pid)
	dir := filepath.Join(root, id)
	if err := os.MkdirAll(filepath.Join(dir, "task", id), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "task", id, "comm"), []byte(comm+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func intPtr(n int) *int { return &n }
