package identity

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseGuestName(t *testing.T) {
	args := []string{
		"qemu-system-x86_64",
		"-name", "guest=payment-prod-03,debug-threads=on",
		"-uuid", "8f3c2a10-1111-2222-3333-444455556666",
		"-netdev", "tap,id=net0,ifname=tap0,script=no",
		"-netdev", "tap,id=net1,ifname=tap1,script=no",
	}
	vm, ok := ParseCmdline(args)
	if !ok {
		t.Fatal("expected qemu")
	}
	if vm.Name != "payment-prod-03" {
		t.Fatalf("name %q", vm.Name)
	}
	if vm.UUID != "8f3c2a10-1111-2222-3333-444455556666" {
		t.Fatalf("uuid %q", vm.UUID)
	}
	if len(vm.Taps) != 2 || vm.Taps[0] != "tap0" || vm.Taps[1] != "tap1" {
		t.Fatalf("taps %#v", vm.Taps)
	}
	if vm.Runtime != "qemu" {
		t.Fatalf("runtime %s", vm.Runtime)
	}
}

func TestParseLibvirtAndKubeVirt(t *testing.T) {
	libvirt := []string{"qemu-system-x86_64", "-name", "postgres-01", "-uuid", "abc", "-pidfile", "/var/run/libvirt/qemu/postgres-01.pid"}
	vm, ok := ParseCmdline(libvirt)
	if !ok || vm.Name != "postgres-01" || vm.Runtime != "libvirt" {
		t.Fatalf("%+v ok=%v", vm, ok)
	}
	kv := []string{"qemu-system-x86_64", "-name", "guest=virt-launcher-api-01"}
	vm, ok = ParseCmdline(kv)
	if !ok || vm.Runtime != "kubevirt" || vm.Name != "virt-launcher-api-01" {
		t.Fatalf("%+v ok=%v", vm, ok)
	}
}

func TestParseRejectsNonQEMU(t *testing.T) {
	if _, ok := ParseCmdline([]string{"sshd", "-D"}); ok {
		t.Fatal("sshd is not a VM")
	}
}

func TestScanProcFixture(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "19321")
	if err := os.MkdirAll(filepath.Join(dir, "task", "19321"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "task", "19322"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := append([]byte("qemu-system-x86_64"), 0)
	cmd = append(cmd, []byte("-name")...)
	cmd = append(cmd, 0)
	cmd = append(cmd, []byte("guest=payment-prod-03,debug-threads=on")...)
	cmd = append(cmd, 0)
	cmd = append(cmd, []byte("-uuid")...)
	cmd = append(cmd, 0)
	cmd = append(cmd, []byte("8f3c2a10-1111-2222-3333-444455556666")...)
	cmd = append(cmd, 0)
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmd, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "comm"), []byte("qemu-system-x86_64\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Noise that must be ignored.
	if err := os.MkdirAll(filepath.Join(root, "1"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "1", "cmdline"), []byte("systemd\x00"), 0o644); err != nil {
		t.Fatal(err)
	}

	vms, err := Scan(root, "node-07")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 {
		t.Fatalf("vms %#v", vms)
	}
	if vms[0].Name != "payment-prod-03" || vms[0].PID != 19321 || vms[0].Hypervisor != "node-07" {
		t.Fatalf("%+v", vms[0])
	}
	if !vms[0].Owns(19322) || vms[0].Owns(1) {
		t.Fatalf("threads %#v", vms[0].Threads)
	}
}

func TestScanMissingRoot(t *testing.T) {
	vms, err := Scan(filepath.Join(t.TempDir(), "missing"), "h")
	if err != nil || len(vms) != 0 {
		t.Fatalf("vms=%v err=%v", vms, err)
	}
}

func TestThreadRoles(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "10")
	for _, tid := range []string{"10", "11", "12", "13"} {
		if err := os.MkdirAll(filepath.Join(dir, "task", tid), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	cmd := []byte("qemu-system-x86_64\x00-name\x00guest=roles\x00")
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), cmd, 0o644); err != nil {
		t.Fatal(err)
	}
	comms := map[string]string{"10": "qemu-system-x86", "11": "CPU 0/KVM", "12": "IO iothread1", "13": "vhost-10"}
	for tid, comm := range comms {
		if err := os.WriteFile(filepath.Join(dir, "task", tid, "comm"), []byte(comm+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	vms, err := Scan(root, "h")
	if err != nil {
		t.Fatal(err)
	}
	if len(vms) != 1 || len(vms[0].ThreadInfo) != 4 {
		t.Fatalf("%+v", vms)
	}
	got := map[int]string{}
	for _, th := range vms[0].ThreadInfo {
		got[th.TID] = th.Role
	}
	if got[10] != "other" || got[11] != "vcpu" || got[12] != "iothread" || got[13] != "vhost" {
		t.Fatalf("%v", got)
	}
}

// tapProc builds a fake /proc/<pid> whose fds include the given links.
func tapProc(t *testing.T, root, pid, cmdline string, fds map[string][2]string) {
	t.Helper()
	dir := filepath.Join(root, pid)
	for _, d := range []string{filepath.Join(dir, "task", pid), filepath.Join(dir, "fd"), filepath.Join(dir, "fdinfo")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmdline), 0o644); err != nil {
		t.Fatal(err)
	}
	for fd, v := range fds { // v = {link target, fdinfo}
		if err := os.Symlink(v[0], filepath.Join(dir, "fd", fd)); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "fdinfo", fd), []byte(v[1]), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTapsFromTunFileDescriptorsForLibvirtVMs(t *testing.T) {
	root := t.TempDir()
	libvirt := "qemu-system-x86_64\x00-name\x00guest=db,debug-threads=on\x00-netdev\x00{\"type\":\"tap\",\"fd\":\"37\",\"id\":\"hostnet0\"}\x00"
	tapProc(t, root, "100", libvirt, map[string][2]string{
		"3":  {"/dev/null", "pos:\t0\nflags:\t02\n"},                      // not a tun
		"37": {"/dev/net/tun", "pos:\t0\nflags:\t0104002\niff:\tvnet1\n"}, // the tap
		"38": {"/dev/net/tun", "pos:\t0\nflags:\t0104002\niff:\tvnet1\n"}, // a second queue of the same tap
		"39": {"/dev/net/tun", "pos:\t0\nflags:\t0104002\niff:\tvnet2\n"}, // a second NIC
		"40": {"/dev/vhost-net", "pos:\t0\n"},                             // vhost, not a tap
	})
	vms, err := Scan(root, "node")
	if err != nil || len(vms) != 1 {
		t.Fatalf("%v %+v", err, vms)
	}
	got := vms[0].Taps
	if len(got) != 2 || got[0] == got[1] {
		t.Fatalf("taps %v: want vnet1 and vnet2 once each", got)
	}
	has := map[string]bool{got[0]: true, got[1]: true}
	if !has["vnet1"] || !has["vnet2"] {
		t.Fatalf("%v", got)
	}
}

func TestCmdlineAndFDTapsAreMergedWithoutDuplicates(t *testing.T) {
	root := t.TempDir()
	cmd := "qemu-system-x86_64\x00-name\x00vm1\x00-netdev\x00tap,id=n0,ifname=tap0,script=no\x00"
	tapProc(t, root, "200", cmd, map[string][2]string{
		"9":  {"/dev/net/tun", "iff:\ttap0\n"}, // the same tap, named both ways
		"10": {"/dev/net/tun", "iff:\ttap1\n"},
	})
	vms, _ := Scan(root, "node")
	if len(vms) != 1 || len(vms[0].Taps) != 2 || vms[0].Taps[0] != "tap0" || vms[0].Taps[1] != "tap1" {
		t.Fatalf("%+v", vms)
	}
}

func TestUnreadableFDsLeaveTheCmdlineTapsAndNeverInventOne(t *testing.T) {
	root := t.TempDir()
	// No fd directory at all, as when the daemon lacks the privilege to read it.
	dir := filepath.Join(root, "300")
	if err := os.MkdirAll(filepath.Join(dir, "task", "300"), 0o755); err != nil {
		t.Fatal(err)
	}
	cmd := "qemu-system-x86_64\x00-name\x00vm1\x00-netdev\x00tap,id=n0,ifname=tapX\x00"
	if err := os.WriteFile(filepath.Join(dir, "cmdline"), []byte(cmd), 0o644); err != nil {
		t.Fatal(err)
	}
	vms, _ := Scan(root, "node")
	if len(vms) != 1 || len(vms[0].Taps) != 1 || vms[0].Taps[0] != "tapX" {
		t.Fatalf("%+v", vms)
	}
	// And a libvirt VM whose fds cannot be read has no known tap, not a guessed one.
	other := t.TempDir()
	libvirt := "qemu-system-x86_64\x00-name\x00guest=web\x00-netdev\x00{\"type\":\"tap\",\"fd\":\"37\"}\x00"
	d2 := filepath.Join(other, "400")
	if err := os.MkdirAll(filepath.Join(d2, "task", "400"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(d2, "cmdline"), []byte(libvirt), 0o644); err != nil {
		t.Fatal(err)
	}
	if v, _ := Scan(other, "node"); len(v) != 1 || len(v[0].Taps) != 0 {
		t.Fatalf("%+v", v)
	}
}
