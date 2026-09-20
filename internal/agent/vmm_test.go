package agent

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/identity"
)

func vmmOpen(ag *Agent, root, pid uint32, comm, path string) {
	ag.Ingest(event.Event{Kind: event.KindVMMOpen, TS: time.Now().UTC(), TGID: root, PID: pid, Comm: comm, Syscall: "openat", Path: path})
}

func vmmCall(ag *Agent, root, pid uint32, comm, call, detail string) {
	ag.Ingest(event.Event{Kind: event.KindVMMCall, TS: time.Now().UTC(), TGID: root, PID: pid, Comm: comm, Syscall: call, Detail: detail})
}

func rules(st interface{ Detections(string) []event.Event }, vm, rule string) []event.Event {
	var out []event.Event
	for _, d := range st.Detections(vm) {
		if d.Rule == rule {
			out = append(out, d)
		}
	}
	return out
}

func TestAShellInAVMMOpeningTheShadowFileIsACriticalDetectionNamingTheVMAndTheProgram(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	vmmOpen(ag, 100, 4321, "cat", "/etc/shadow")
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 1 || d[0].Severity != "critical" || d[0].VM.Name != "db" || d[0].GuestAttributed || d[0].Attribution != event.AttributionQEMU ||
		d[0].Message != "cat (pid 4321) in db's VMM process tree opened /etc/shadow, which matches /etc/shadow: a VMM has no reason to" {
		t.Fatalf("%+v", d)
	}
	// the event itself is kept, and belongs to the VM, with the VMM as its process
	var ev []event.Event
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen {
			ev = append(ev, e)
		}
	}
	if len(ev) != 1 || ev[0].TGID != 100 || ev[0].PID != 4321 || ev[0].Path != "/etc/shadow" || ev[0].Attribution != event.AttributionQEMU {
		t.Fatalf("%+v", ev)
	}
}

func TestAnOpenForWritingSaysSo(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	ag.Ingest(event.Event{Kind: event.KindVMMOpen, TS: time.Now().UTC(), TGID: 100, PID: 9, Comm: "sh", Syscall: "openat", Path: "/root/.ssh/authorized_keys", Write: true})
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 1 || !strings.Contains(d[0].Message, "opened for writing /root/.ssh/authorized_keys, which matches /root/.ssh") {
		t.Fatalf("%+v", d)
	}
}

func TestWhatAVMMOpensThatIsNotSensitiveIsAnEventAndNothingMore(t *testing.T) {
	ag, st := newTapAgent(t, "")
	vmmOpen(ag, 100, 100, "qemu-system-x86", "/var/lib/libvirt/images/db.qcow2")
	if len(st.Detections("db")) != 0 {
		t.Fatalf("%+v", st.Detections("db"))
	}
	if n := len(st.Events("db")); n != 1 {
		t.Fatalf("the open is still recorded: %d", n)
	}
}

func TestAPathIsJudgedAfterItIsCleanedAndAThreadOfTheVMMIsTheVMM(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	st.SetVMs([]identity.VM{{Name: "db", UUID: "u1", Runtime: "qemu", PID: 100, Threads: []int{100, 101}}})
	vmmOpen(ag, 101, 500, "cat", "/etc/../etc//shadow") // 101 is a thread of db
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 1 {
		t.Fatalf("%+v", d)
	}
	var got event.Event
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen {
			got = e
		}
	}
	if got.TGID != 100 {
		t.Fatalf("the event names the VMM, not the thread the kernel found: %d", got.TGID)
	}
}

func TestAVMMTheScanDoesNotKnowIsRecordedWithoutAVMAndRaisesNothing(t *testing.T) {
	ag, st := newTapAgent(t, "")
	vmmOpen(ag, 99999, 1, "cat", "/etc/shadow")
	vmmCall(ag, 99999, 1, "gdb", "ptrace", "request 16 (ATTACH) on pid 5")
	if len(st.Detections("")) != 0 {
		t.Fatalf("there is no VM to say it about: %+v", st.Detections(""))
	}
	n := 0
	for _, e := range st.Events("") {
		if e.Kind == event.KindVMMOpen || e.Kind == event.KindVMMCall {
			n++
			if e.VM.Name != "" {
				t.Fatalf("%+v", e)
			}
		}
	}
	if n != 2 {
		t.Fatalf("both are kept: %d", n)
	}
}

// fakeProc makes a /proc under the agent's root with a process whose working directory and descriptor are known.
func fakeProc(t *testing.T, ag *Agent, pid int, cwd string, fds map[int]string) {
	t.Helper()
	dir := filepath.Join(ag.ProcRoot, strconv.Itoa(pid))
	if err := os.MkdirAll(filepath.Join(dir, "fd"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(cwd, filepath.Join(dir, "cwd")); err != nil {
		t.Fatal(err)
	}
	for fd, target := range fds {
		if err := os.Symlink(target, filepath.Join(dir, "fd", strconv.Itoa(fd))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestARelativePathIsResolvedFromTheProcessesWorkingDirectoryWhileItIsThere(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	fakeProc(t, ag, 4321, "/etc", nil)
	vmmOpen(ag, 100, 4321, "cat", "shadow") // cd /etc; cat shadow
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 1 || !strings.Contains(d[0].Message, "opened /etc/shadow, which matches /etc/shadow") {
		t.Fatalf("%+v", d)
	}
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen {
			if e.Path != "/etc/shadow" || e.Detail != `opened as "shadow", resolved from the process's working directory (/etc)` {
				t.Fatalf("the event says what it was and how it was resolved: %+v", e)
			}
		}
	}
}

func TestARelativePathToADescriptorIsResolvedFromWhatTheDescriptorNames(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	fakeProc(t, ag, 4322, "/tmp", map[int]string{9: "/etc/ssh"})
	ag.Ingest(event.Event{Kind: event.KindVMMOpen, TS: time.Now().UTC(), TGID: 100, PID: 4322, Comm: "sh", Syscall: "openat", Path: "ssh_host_rsa_key", Detail: "relative to fd 9"})
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 1 || !strings.Contains(d[0].Message, "/etc/ssh/ssh_host_rsa_key, which matches /etc/ssh") {
		t.Fatalf("%+v", d)
	}
	// a descriptor that is not there leaves it as given, and the working directory is not a substitute for it
	ag.Ingest(event.Event{Kind: event.KindVMMOpen, TS: time.Now().UTC(), TGID: 100, PID: 4322, Comm: "sh", Syscall: "openat", Path: "shadow", Detail: "relative to fd 77"})
	if len(rules(st, "db", "vmm-sensitive-open")) != 1 {
		t.Fatal("a descriptor that cannot be read must not fall back to the working directory")
	}
}

func TestARelativePathFromAProcessThatIsGoneCannotBeJudgedAndIsLeftAsGiven(t *testing.T) {
	ag, st := newTapAgent(t, "")
	vmmOpen(ag, 100, 777, "cat", "shadow") // no /proc/777
	vmmOpen(ag, 100, 0, "cat", "shadow")   // no pid at all
	if len(st.Detections("db")) != 0 {
		t.Fatalf("%+v", st.Detections("db"))
	}
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen && (e.Path != "shadow" || e.Detail != "") {
			t.Fatalf("%+v", e)
		}
	}
	// a working directory that is not a path (a deleted directory reads as "/x (deleted)", which is still one; a
	// garbage link is not) is not used
	fakeProc(t, ag, 778, "relative-nonsense", nil)
	vmmOpen(ag, 100, 778, "cat", "shadow")
	for _, e := range st.Events("db") {
		if e.PID == 778 && e.Path != "shadow" {
			t.Fatalf("%+v", e)
		}
	}
}

func TestEachCallAVMMHasNoBusinessMakingIsADetectionWithTheSeverityItDeserves(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	for call, sev := range map[string]string{"ptrace": "critical", "process_vm_writev": "critical", "finit_module": "critical", "kexec_load": "critical", "mount": "high", "unshare": "high", "setns": "high", "process_vm_readv": "high"} {
		vmmCall(ag, 100, 4321, "sh", call, "detail here")
		found := false
		for _, d := range rules(st, "db", "vmm-syscall") {
			if strings.Contains(d.Message, "called "+call+" (detail here)") {
				found = true
				if d.Severity != sev || d.GuestAttributed || d.VM.Name != "db" {
					t.Fatalf("%s: %+v", call, d)
				}
			}
		}
		if !found {
			t.Fatalf("no detection for %s", call)
		}
	}
	vmmCall(ag, 100, 4321, "sh", "init_module", "")
	if d := rules(st, "db", "vmm-syscall"); !strings.HasSuffix(d[len(d)-1].Message, "called init_module: a VMM has no business doing that") {
		t.Fatalf("with no detail there are no empty brackets: %q", d[len(d)-1].Message)
	}
}

func TestAFloodIsACriticalDetectionSayingHowMany(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	ag.Ingest(event.Event{Kind: event.KindVMMCall, TS: time.Now().UTC(), TGID: 100, PID: 100, Comm: "qemu-system-x86", Syscall: "flood", Count: 1234})
	d := rules(st, "db", "vmm-flood")
	if len(d) != 1 || d[0].Severity != "critical" || !strings.Contains(d[0].Message, "1234 more file opens and calls in a second") {
		t.Fatalf("%+v", d)
	}
}

func TestTheSameThingByTheSameProgramIsOneDetectionButAnotherFileOrProgramIsNot(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	vmmOpen(ag, 100, 1, "cat", "/etc/shadow")
	vmmOpen(ag, 100, 2, "cat", "/etc/shadow")  // another pid, the same thing
	vmmOpen(ag, 100, 3, "cat", "/etc//shadow") // the same file spelled another way
	if len(rules(st, "db", "vmm-sensitive-open")) != 1 || st.Suppressed() != 2 {
		t.Fatalf("%d detections, %d suppressed", len(rules(st, "db", "vmm-sensitive-open")), st.Suppressed())
	}
	vmmOpen(ag, 100, 4, "cat", "/etc/gshadow") // another file
	vmmOpen(ag, 100, 5, "less", "/etc/shadow") // another program
	vmmOpen(ag, 200, 6, "cat", "/etc/shadow")  // another VM
	if len(rules(st, "db", "vmm-sensitive-open")) != 3 || len(rules(st, "web", "vmm-sensitive-open")) != 1 {
		t.Fatalf("db %d web %d", len(rules(st, "db", "vmm-sensitive-open")), len(rules(st, "web", "vmm-sensitive-open")))
	}
	vmmCall(ag, 100, 7, "sh", "unshare", "a")
	vmmCall(ag, 100, 8, "sh", "unshare", "b") // the same call by the same program, whatever the arguments
	vmmCall(ag, 100, 9, "sh", "mount", "")    // another call
	if len(rules(st, "db", "vmm-syscall")) != 2 {
		t.Fatalf("%d", len(rules(st, "db", "vmm-syscall")))
	}
}

func TestTheRulesFileAddsPathsExemptsOthersAndNarrowsTheCalls(t *testing.T) {
	ag, st := newTapAgent(t, `
suppress: 5m
vmm:
  paths: [/srv/secrets]
  ignore: [/root/.ssh/known_hosts]
  syscalls: [ptrace]
  severity: high
`)
	vmmOpen(ag, 100, 1, "cat", "/srv/secrets/db.key")
	vmmOpen(ag, 100, 2, "ssh", "/root/.ssh/known_hosts")
	vmmOpen(ag, 100, 3, "cat", "/etc/shadow")
	d := rules(st, "db", "vmm-sensitive-open")
	if len(d) != 2 || d[0].Severity != "high" || d[1].Severity != "high" {
		t.Fatalf("%+v", d)
	}
	for _, x := range d {
		if strings.Contains(x.Message, "known_hosts") {
			t.Fatalf("an exempted path was reported: %+v", x)
		}
	}
	vmmCall(ag, 100, 4, "sh", "mount", "")
	vmmCall(ag, 100, 5, "sh", "ptrace", "")
	if got := rules(st, "db", "vmm-syscall"); len(got) != 1 || !strings.Contains(got[0].Message, "called ptrace") {
		t.Fatalf("only the named call: %+v", got)
	}
}

func TestAnAbsolutePathIsNeverResolvedAgainstTheWorkingDirectory(t *testing.T) {
	ag, st := newTapAgent(t, "suppress: 5m\n")
	fakeProc(t, ag, 4400, "/tmp", nil)
	vmmOpen(ag, 100, 4400, "cat", "/etc/shadow")
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen && (e.Path != "/etc/shadow" || e.Detail != "") {
			t.Fatalf("an absolute path is what it says: %+v", e)
		}
	}
	if len(rules(st, "db", "vmm-sensitive-open")) != 1 {
		t.Fatal("and is judged as it is")
	}
}

func TestNoResolvingIsDoneForProcessZeroOrForADescriptorThatCannotBeOne(t *testing.T) {
	ag, st := newTapAgent(t, "")
	fakeProc(t, ag, 0, "/etc", nil) // there is a directory named 0, but a call with no process is not its cwd
	vmmOpen(ag, 100, 0, "cat", "shadow")
	fakeProc(t, ag, 4401, "/tmp", map[int]string{-5: "/etc"})
	ag.Ingest(event.Event{Kind: event.KindVMMOpen, TS: time.Now().UTC(), TGID: 100, PID: 4401, Comm: "cat", Syscall: "openat", Path: "shadow", Detail: "relative to fd -5"})
	for _, e := range st.Events("db") {
		if e.Kind == event.KindVMMOpen && (e.Path != "shadow" || strings.HasPrefix(e.Detail, "opened as")) {
			t.Fatalf("%+v", e)
		}
	}
	if len(st.Detections("db")) != 0 {
		t.Fatalf("%+v", st.Detections("db"))
	}
}
