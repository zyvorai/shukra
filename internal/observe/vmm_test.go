package observe

import (
	"encoding/binary"
	"sort"
	"strings"
	"testing"

	"github.com/zyvorai/shukra/internal/event"
)

// vmmSample lays out a vmm_events record by offset, the way bpf/vmm.bpf.c does. The path buffer is filled past
// pathlen with what an earlier record could have left there.
func vmmSample(call, root, pid uint32, comm, path string, pathlen int, flags uint32, dfd int32, a0, a1 uint64) []byte {
	b := make([]byte, vmmEventSize)
	binary.LittleEndian.PutUint32(b[8:12], root)
	binary.LittleEndian.PutUint32(b[12:16], pid)
	binary.LittleEndian.PutUint32(b[16:20], pid+1000) // a thread of it, not the process itself
	binary.LittleEndian.PutUint32(b[20:24], call)
	binary.LittleEndian.PutUint32(b[24:28], uint32(dfd))
	binary.LittleEndian.PutUint32(b[28:32], flags)
	binary.LittleEndian.PutUint64(b[32:40], a0)
	binary.LittleEndian.PutUint64(b[40:48], a1)
	binary.LittleEndian.PutUint16(b[48:50], uint16(pathlen))
	copy(b[vmmCommOff:vmmCommOff+16], comm)
	stale := []byte(strings.Repeat("/etc/shadow-left-by-an-earlier-record", 8))
	copy(b[vmmPathOff:vmmPathOff+vmmPathMax], stale)
	copy(b[vmmPathOff:], path+"\x00") // the kernel writes the string and its NUL, and nothing after
	return b
}

func open(call uint32, path string, flags uint32, dfd int32) []byte {
	return vmmSample(call, 100, 200, "cat", path, len(path)+1, flags, dfd, 0, 0)
}

func TestAnOpenIsReadByOffsetWithTheProcessThatMadeItAndTheVMMItBelongsTo(t *testing.T) {
	e, ok := decodeVMM(open(vmmOpenat, "/etc/shadow", 0, atFDCWD), nil)
	if !ok || e.Kind != event.KindVMMOpen || e.Syscall != "openat" || e.Path != "/etc/shadow" || e.Comm != "cat" || e.PID != 200 || e.TGID != 100 || e.Write || e.Detail != "" {
		t.Fatalf("%+v %v", e, ok)
	}
	for call, name := range map[uint32]string{vmmOpenat2: "openat2", vmmOpen: "open"} {
		if e, ok := decodeVMM(open(call, "/x", 0, atFDCWD), nil); !ok || e.Kind != event.KindVMMOpen || e.Syscall != name {
			t.Fatalf("%s: %+v %v", name, e, ok)
		}
	}
}

func TestAnOpenThatAsksToWriteSaysSoAndOpenat2IsNotGuessedAt(t *testing.T) {
	for name, tc := range map[string]struct {
		call  uint32
		flags uint32
		want  bool
	}{
		"read only":          {vmmOpenat, 0, false},
		"write only":         {vmmOpenat, 1, true},
		"read and write":     {vmmOpenat, 2, true},
		"create":             {vmmOpenat, 0x40, true},
		"truncate":           {vmmOpenat, 0x200, true},
		"a flag that is not": {vmmOpenat, 0x80000, false},
		"legacy open write":  {vmmOpen, 1, true},
		"openat2 has its flags in a struct, not seen": {vmmOpenat2, 1, false},
	} {
		if e, _ := decodeVMM(open(tc.call, "/x", tc.flags, atFDCWD), nil); e.Write != tc.want {
			t.Fatalf("%s: write=%v", name, e.Write)
		}
	}
}

func TestAPathThatIsRelativeToADescriptorSaysWhichAndOneRelativeToTheWorkingDirectoryDoesNot(t *testing.T) {
	if e, _ := decodeVMM(open(vmmOpenat, "shadow", 0, 7), nil); e.Path != "shadow" || e.Detail != "relative to fd 7" {
		t.Fatalf("%+v", e)
	}
	if e, _ := decodeVMM(open(vmmOpenat, "shadow", 0, atFDCWD), nil); e.Path != "shadow" || e.Detail != "" {
		t.Fatalf("relative to the working directory is what a plain relative path means: %+v", e)
	}
	if e, _ := decodeVMM(open(vmmOpenat, "/etc/shadow", 0, 7), nil); e.Detail != "" {
		t.Fatalf("an absolute path ignores the descriptor: %+v", e)
	}
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "x", "", 0, 0, 7, 0, 0), nil); e.Detail != "" || e.Path != "" {
		t.Fatalf("no path, nothing relative: %+v", e)
	}
}

func TestOnlyWhatThePathLengthSaysIsThePathAndWhatWasLeftInTheBufferIsNeverRead(t *testing.T) {
	// the buffer holds a longer, stale path after the real one
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "x", "/a", 3, 0, atFDCWD, 0, 0), nil); e.Path != "/a" {
		t.Fatalf("%q", e.Path)
	}
	// a length shorter than the string stops at the length
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "x", "/abcdef", 3, 0, atFDCWD, 0, 0), nil); e.Path != "/ab" {
		t.Fatalf("%q", e.Path)
	}
	// a path that could not be read is empty, not what was there before
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "x", "/abc", 0, 0, atFDCWD, 0, 0), nil); e.Path != "" {
		t.Fatalf("%q", e.Path)
	}
	// a length past the buffer is cut to it
	long := strings.Repeat("a", 400)
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "x", long, 65535, 0, atFDCWD, 0, 0), nil); len(e.Path) != vmmPathMax {
		t.Fatalf("%d", len(e.Path))
	}
	// and the record is exactly as long as the program says, so the path is never read past it
	if e, ok := decodeVMM(open(vmmOpenat, "/x", 0, atFDCWD)[:vmmEventSize-1], nil); ok {
		t.Fatalf("a short record was decoded: %+v", e)
	}
}

func TestAPathFromAProcessIsMadePrintableButKeepsItsCase(t *testing.T) {
	for name, tc := range map[string]struct{ in, want string }{
		"case is kept":     {"/Etc/Shadow", "/Etc/Shadow"},
		"a space is kept":  {"/a b", "/a b"},
		"escape and lines": {"/a\x1b[31m\nb", "/a?[31m?b"},
		"high bytes":       {"/\xff\xfe", "/??"},
		"a tab":            {"/a\tb", "/a?b"},
		"a delete":         {"/a\x7fb", "/a?b"},
	} {
		if e, _ := decodeVMM(open(vmmOpenat, tc.in, 0, atFDCWD), nil); e.Path != tc.want {
			t.Fatalf("%s: %q, want %q", name, e.Path, tc.want)
		}
	}
	// the process name is made safe too, and a name that fills all sixteen bytes has no NUL
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "a\x1bb", "/x", 3, 0, atFDCWD, 0, 0), nil); e.Comm != "a?b" {
		t.Fatalf("%q", e.Comm)
	}
	if e, _ := decodeVMM(vmmSample(vmmOpenat, 1, 2, "0123456789abcdef", "/x", 3, 0, atFDCWD, 0, 0), nil); e.Comm != "0123456789abcdef" {
		t.Fatalf("%q", e.Comm)
	}
}

func TestEveryOtherCallIsAVMMCallThatReadsItsArgumentsInWords(t *testing.T) {
	for name, tc := range map[string]struct {
		call   uint32
		a0, a1 uint64
		want   string
	}{
		"ptrace attach":    {vmmPtrace, 16, 1234, "request 16 (ATTACH) on pid 1234"},
		"ptrace seize":     {vmmPtrace, 0x4206, 7, "request 16902 (SEIZE) on pid 7"},
		"ptrace unknown":   {vmmPtrace, 99, 5, "request 99 on pid 5"},
		"write memory":     {vmmProcessVMWritev, 4321, 0, "writes the memory of pid 4321"},
		"read memory":      {vmmProcessVMReadv, 4321, 0, "reads the memory of pid 4321"},
		"mount":            {vmmMount, 0x1000, 0, "flags 0x1000"},
		"unshare mount ns": {vmmUnshare, 0x20000, 0, "new mount namespace"},
		"unshare several":  {vmmUnshare, 0x20000 | 0x40000000 | 0x10000000, 0, "new mount, user, net namespace"},
		"unshare nothing":  {vmmUnshare, 0, 0, "no namespace flag"},
		"setns":            {vmmSetns, 9, 0x20000, "into the namespace of fd 9, type 0x20000"},
		"finit_module":     {vmmFinitModule, 3, 1, "module fd 3, flags 0x1"},
		"init_module":      {vmmInitModule, 0, 0, ""},
		"kexec_load":       {vmmKexecLoad, 0, 0, ""},
		"kexec_file_load":  {vmmKexecFileLoad, 0, 0, ""},
	} {
		e, ok := decodeVMM(vmmSample(tc.call, 100, 200, "x", "", 0, 0, 0, tc.a0, tc.a1), nil)
		if !ok || e.Kind != event.KindVMMCall || e.Syscall != vmmCalls[tc.call] || e.Detail != tc.want || e.Path != "" || e.Write {
			t.Fatalf("%s: %+v %v", name, e, ok)
		}
	}
}

func TestANegativePidReadsAsNegativeNotAsFourBillion(t *testing.T) {
	e, _ := decodeVMM(vmmSample(vmmPtrace, 1, 2, "x", "", 0, 0, 0, 16, uint64(0xffffffff)), nil)
	if e.Detail != "request 16 (ATTACH) on pid -1" {
		t.Fatalf("%q", e.Detail)
	}
}

func TestAFloodSaysHowManyCallsWereNotReported(t *testing.T) {
	e, ok := decodeVMM(vmmSample(vmmFlood, 100, 100, "qemu-system-x86", "", 0, 0, 0, 1234, 0), nil)
	if !ok || e.Kind != event.KindVMMCall || e.Syscall != "flood" || e.Count != 1234 || e.TGID != 100 {
		t.Fatalf("%+v %v", e, ok)
	}
}

func TestACallThisBuildDoesNotKnowIsLostAndNeverGuessedAt(t *testing.T) {
	for _, call := range []uint32{0, 4, 9, 20, 254, 4000} {
		if e, ok := decodeVMM(vmmSample(call, 1, 2, "x", "/x", 3, 0, 0, 0, 0), nil); ok {
			t.Fatalf("call %d: %+v", call, e)
		}
	}
}

func TestTheNamesTheRulesFileMayUseAreExactlyTheCallsThatAreNotOpens(t *testing.T) {
	var want []string
	for call, name := range vmmCalls {
		switch call {
		case vmmOpenat, vmmOpenat2, vmmOpen, vmmFlood:
		default:
			want = append(want, name)
		}
	}
	got := VMMSyscallNames()
	sort.Strings(want)
	sort.Strings(got)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%v, want %v", got, want)
	}
}
