package observe

import "testing"

func TestAPreemptorThatIsAQEMUThreadIsNamedByItsVMAndAnyOtherByItsCommand(t *testing.T) {
	owners := func(tid uint32) (ThreadRef, bool) {
		switch tid {
		case 11:
			return ThreadRef{VM: "web", Role: "vcpu"}, true
		case 12:
			return ThreadRef{VM: "db", Role: "iothread"}, true
		case 13:
			return ThreadRef{Role: "vcpu"}, true // a thread the scan could not name a VM for
		}
		return ThreadRef{}, false
	}
	for _, x := range []struct {
		tid  uint32
		comm string
		want string
	}{
		{11, "CPU 3/KVM", "vm:web"}, // the comm says nothing about which VM: the owner does
		{12, "IO iothread1", "vm:db"},
		{13, "CPU 0/KVM", "CPU 0"}, // no VM to name, so the command, cut at the slash like any other
		{900, "kworker/3:1", "kworker"},
		{901, "kworker/u16:2", "kworker"}, // one preemptor, however many instances
		{902, "ksoftirqd/7", "ksoftirqd"},
		{903, "migration/0", "migration"},
		{904, "  node_exporter ", "node_exporter"},
		{905, "", "unknown"},
		{906, "/x", "/x"}, // a slash at the very start is not a suffix
	} {
		if got := preemptorLabel(x.tid, x.comm, owners); got != x.want {
			t.Errorf("tid %d comm %q: %q, want %q", x.tid, x.comm, got, x.want)
		}
	}
}

func TestThreadTableIsReplacedNotMerged(t *testing.T) {
	SetThreads(map[uint32]ThreadRef{1: {VM: "a", Role: "vcpu"}})
	SetThreads(map[uint32]ThreadRef{2: {VM: "b", Role: "vcpu"}})
	if _, ok := threadRef(1); ok {
		t.Fatal("a thread from the previous scan is still owned: a reused tid would be attributed to a VM that is gone")
	}
	if r, ok := threadRef(2); !ok || r.VM != "b" {
		t.Fatalf("%+v %v", r, ok)
	}
	SetThreads(nil)
}

func TestCommStringStopsAtTheFirstNUL(t *testing.T) {
	var b [16]byte
	copy(b[:], "kworker/3:1\x00garbage")
	if got := commString(b); got != "kworker/3:1" {
		t.Fatalf("%q", got)
	}
	var full [16]byte
	copy(full[:], "0123456789abcdef")
	if got := commString(full); got != "0123456789abcdef" {
		t.Fatalf("a comm that fills the array has no NUL: %q", got)
	}
	if got := commString([16]byte{}); got != "" {
		t.Fatalf("%q", got)
	}
}
