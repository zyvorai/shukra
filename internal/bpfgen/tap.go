//go:build linux && shukrabpf

package bpfgen

import (
	"errors"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

// TapPinDir is where the tap program's maps and TCX links are pinned, so that
// enforcement outlives the daemon: a crash or restart leaves an isolated VM
// isolated, and the next start adopts what is there. It is a variable so tests
// can point it elsewhere.
var TapPinDir = "/sys/fs/bpf/shukra/tap"

const bpffsMagic = 0xcafe4a11

// TapStat is the sum over CPUs of one tap's counters, from the guest's point of
// view: From is what the guest sent, To is what was sent to it.
type TapStat struct {
	FromPkts, FromBytes       uint64
	ToPkts, ToBytes           uint64
	DroppedPkts, DroppedBytes uint64
}

// tapStatC mirrors struct tap_stat in bpf/tap.bpf.c.
type tapStatC struct {
	FromPkts, FromBytes, ToPkts, ToBytes, DroppedPkts, DroppedBytes uint64
}

type tapPolicyC struct {
	Isolated uint8
	_        [7]uint8
}

type lpm4Key struct {
	Prefixlen uint32
	Addr      [4]byte
}

type lpm6Key struct {
	Prefixlen uint32
	Addr      [16]byte
}

type tapLinks struct {
	ifindex  uint32
	in, out  link.Link
	isolated bool
}

func (t *tapLinks) close() {
	_ = t.in.Close()
	_ = t.out.Close()
}

// unpin removes the pins, which is what actually detaches a pinned link once the
// process's own handles are closed.
func (t *tapLinks) unpin() {
	_ = t.in.Unpin()
	_ = t.out.Unpin()
}

// The tap program is not attached once at start like the others: it goes on each
// VM's tap as VMs appear and comes off as they go. This is the one place that
// knows which interfaces have it.
var tapMgr struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	coll    *ebpf.Collection
	taps    map[string]*tapLinks
	pinned  bool // maps and links are pinned, so they survive this process
}

// preparePins makes the pin directory, and reports whether it is on a bpf
// filesystem. Without one the program still works, but only while the daemon runs.
func preparePins() bool {
	if err := os.MkdirAll(TapPinDir, 0o700); err != nil {
		return false
	}
	var st unix.Statfs_t
	if err := unix.Statfs(TapPinDir, &st); err != nil || uint32(st.Type) != bpffsMagic {
		return false
	}
	return true
}

func linkPin(name, dir string) string {
	return filepath.Join(TapPinDir, "link-"+name+"-"+dir)
}

// wipePins removes everything pinned for the tap program, detaching its links.
func wipePins() int {
	entries, err := os.ReadDir(TapPinDir)
	if err != nil {
		return 0
	}
	n := 0
	for _, e := range entries {
		path := filepath.Join(TapPinDir, e.Name())
		if strings.HasPrefix(e.Name(), "link-") {
			if l, err := link.LoadPinnedLink(path, nil); err == nil {
				_ = l.Unpin()
				_ = l.Close()
				n++
				continue
			}
		}
		_ = os.Remove(path)
	}
	return n
}

func loadTapLocked() error {
	if tapMgr.loaded {
		return tapMgr.loadErr
	}
	tapMgr.loaded = true
	tapMgr.taps = map[string]*tapLinks{}
	spec, err := LoadTap()
	if err != nil {
		tapMgr.loadErr = err
		return err
	}
	tapMgr.pinned = preparePins()
	var opts ebpf.CollectionOptions
	if tapMgr.pinned {
		opts.Maps.PinPath = TapPinDir
	} else {
		// No bpf filesystem: run unpinned. Enforcement then lasts only as long as
		// the daemon, and the status says so.
		log.Printf("tap program: %s is not a bpf filesystem, so enforcement will not outlive the daemon", TapPinDir)
		for _, m := range spec.Maps {
			m.Pinning = ebpf.PinNone
		}
	}
	coll, err := ebpf.NewCollectionWithOptions(spec, opts)
	if err != nil && tapMgr.pinned && errors.Is(err, ebpf.ErrMapIncompatible) {
		// The pins are from a build whose maps look different. They cannot be
		// reused, so start clean. The recorded isolations are re-applied by the
		// daemon, so nothing is lost but a brief gap.
		log.Printf("tap program: pinned maps from another version cannot be reused, replacing them (%v)", err)
		wipePins()
		coll, err = ebpf.NewCollectionWithOptions(spec, opts)
	}
	if err != nil {
		tapMgr.loadErr = fmt.Errorf("loading the tap program: %w", err)
		return tapMgr.loadErr
	}
	tapMgr.coll = coll
	return nil
}

// TapPinned reports whether the tap program's maps and links are pinned, so that
// enforcement survives the daemon.
func TapPinned() bool {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	return tapMgr.pinned
}

// TapStatus reports whether the tap program is loaded and how many taps have it.
func TapStatus() (loaded bool, taps int, err error) {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	if err := loadTapLocked(); err != nil {
		return false, 0, err
	}
	return true, len(tapMgr.taps), nil
}

// TapCollection is the loaded collection, for the event ring reader. Nil if the
// program could not be loaded.
func TapCollection() *ebpf.Collection {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	_ = loadTapLocked()
	return tapMgr.coll
}

// TapName maps an interface index back to the tap name it was attached under.
func TapName(ifindex uint32) string {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	for name, t := range tapMgr.taps {
		if t.ifindex == ifindex {
			return name
		}
	}
	return ""
}

// SyncTaps makes the set of tapped interfaces equal to names. A name whose
// interface does not exist yet is skipped, and is tried again on the next call.
// An interface that goes away, or comes back under a new index, is detached and
// its isolation flag cleared, so a reused index never inherits it. The errors are
// per interface; the rest are still synced.
func SyncTaps(names []string) (map[string]error, error) {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	if err := loadTapLocked(); err != nil {
		return nil, err
	}
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	for name, t := range tapMgr.taps {
		cur, err := net.InterfaceByName(name)
		if !want[name] || err != nil || uint32(cur.Index) != t.ifindex {
			detachTapLocked(name)
		}
	}
	dropOrphansLocked(want)
	errs := map[string]error{}
	for name := range want {
		if _, ok := tapMgr.taps[name]; ok {
			continue
		}
		iface, err := net.InterfaceByName(name)
		if err != nil {
			continue // not created yet
		}
		if err := attachTapLocked(name, uint32(iface.Index)); err != nil {
			errs[name] = err
		}
	}
	return errs, nil
}

// adoptLocked takes over links a previous process pinned for this tap, pointing
// them at the program this process just loaded. It reads the isolation flag back
// from the pinned policy map, so what the kernel is enforcing is what is reported.
func adoptLocked(name string, ifindex uint32) bool {
	if !tapMgr.pinned || strings.ContainsRune(name, '/') {
		return false
	}
	in, err1 := link.LoadPinnedLink(linkPin(name, "in"), nil)
	out, err2 := link.LoadPinnedLink(linkPin(name, "out"), nil)
	fail := func() bool {
		if in != nil {
			_ = in.Unpin()
			_ = in.Close()
		}
		if out != nil {
			_ = out.Unpin()
			_ = out.Close()
		}
		return false
	}
	if err1 != nil || err2 != nil {
		return fail()
	}
	for _, l := range []link.Link{in, out} {
		info, err := l.Info()
		if err != nil || info.TCX() == nil || info.TCX().Ifindex != ifindex {
			return fail() // pinned for an interface that has since been replaced
		}
	}
	if err := in.Update(tapMgr.coll.Programs["shukra_tap_from_guest"]); err != nil {
		return fail()
	}
	if err := out.Update(tapMgr.coll.Programs["shukra_tap_to_guest"]); err != nil {
		return fail()
	}
	var pol tapPolicyC
	isolated := tapMgr.coll.Maps["tap_policy"].Lookup(ifindex, &pol) == nil && pol.Isolated != 0
	tapMgr.taps[name] = &tapLinks{ifindex: ifindex, in: in, out: out, isolated: isolated}
	return true
}

func attachTapLocked(name string, ifindex uint32) error {
	if adoptLocked(name, ifindex) {
		return nil
	}
	in, err := link.AttachTCX(link.TCXOptions{
		Interface: int(ifindex), Program: tapMgr.coll.Programs["shukra_tap_from_guest"], Attach: ebpf.AttachTCXIngress,
	})
	if err != nil {
		if errors.Is(err, link.ErrNotSupported) {
			return errors.New("TCX needs Linux 6.6 or newer")
		}
		return err
	}
	out, err := link.AttachTCX(link.TCXOptions{
		Interface: int(ifindex), Program: tapMgr.coll.Programs["shukra_tap_to_guest"], Attach: ebpf.AttachTCXEgress,
	})
	if err != nil {
		in.Close()
		return err
	}
	t := &tapLinks{ifindex: ifindex, in: in, out: out}
	if tapMgr.pinned && !strings.ContainsRune(name, '/') {
		if err := in.Pin(linkPin(name, "in")); err != nil {
			t.close()
			return fmt.Errorf("pinning the ingress link: %w", err)
		}
		if err := out.Pin(linkPin(name, "out")); err != nil {
			t.unpin()
			t.close()
			return fmt.Errorf("pinning the egress link: %w", err)
		}
	}
	tapMgr.taps[name] = t
	return nil
}

func detachTapLocked(name string) {
	t := tapMgr.taps[name]
	if t == nil {
		return
	}
	t.unpin()
	t.close()
	_ = tapMgr.coll.Maps["tap_policy"].Delete(t.ifindex)
	clearOutcomesLocked(t.ifindex)
	delete(tapMgr.taps, name)
}

// dropOrphansLocked detaches taps a previous process pinned that no VM wants any
// more, such as a VM that went away while the daemon was down.
func dropOrphansLocked(want map[string]bool) {
	if !tapMgr.pinned {
		return
	}
	matches, _ := filepath.Glob(filepath.Join(TapPinDir, "link-*-in"))
	for _, in := range matches {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(in), "link-"), "-in")
		if want[name] || tapMgr.taps[name] != nil {
			continue
		}
		var ifindex uint32
		if l, err := link.LoadPinnedLink(in, nil); err == nil {
			if info, err := l.Info(); err == nil && info.TCX() != nil {
				ifindex = info.TCX().Ifindex
			}
			_ = l.Unpin()
			_ = l.Close()
		}
		if out, err := link.LoadPinnedLink(linkPin(name, "out"), nil); err == nil {
			_ = out.Unpin()
			_ = out.Close()
		}
		if ifindex != 0 {
			_ = tapMgr.coll.Maps["tap_policy"].Delete(ifindex)
		}
	}
}

// ShutdownTaps is the daemon's graceful exit. A tap that is not isolated is
// detached, so nothing of Shukra is left on a VM's interface once it is off. An
// isolated tap is left enforcing: the point of pinning is that stopping the daemon
// must not reopen a VM that was cut off. A crash skips this and leaves every tap as
// it was, for the next start to adopt.
func ShutdownTaps() (kept, detached int) {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	for name, t := range tapMgr.taps {
		if tapMgr.pinned && t.isolated {
			t.close() // the pins keep the link attached
			kept++
		} else {
			detachTapLocked(name)
			detached++
		}
	}
	tapMgr.taps = map[string]*tapLinks{}
	return kept, detached
}

// DetachAllTaps removes everything the tap program has pinned, isolated or not, so
// an operator can undo enforcement by hand or an uninstall can leave nothing behind.
// It needs no loaded program, so it works when the daemon is not running.
func DetachAllTaps() int {
	return wipePins()
}

// TapAttached lists the tap names that currently carry the program.
func TapAttached() []string {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	var out []string
	for n := range tapMgr.taps {
		out = append(out, n)
	}
	return out
}

// SetTapIsolated turns isolation on or off for one attached tap.
func SetTapIsolated(name string, on bool) error {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	t := tapMgr.taps[name]
	if t == nil {
		return fmt.Errorf("tap %s does not carry the program", name)
	}
	pol := tapPolicyC{}
	if on {
		pol.Isolated = 1
	}
	if err := tapMgr.coll.Maps["tap_policy"].Put(t.ifindex, pol); err != nil {
		return err
	}
	t.isolated = on
	return nil
}

// TapIsolated reports the isolation flag userspace last set for a tap.
func TapIsolated(name string) bool {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	t := tapMgr.taps[name]
	return t != nil && t.isolated
}

// SetTapAllow replaces the management allow list. It is loaded whether or not any
// tap is attached yet, since it must be in place before the first isolation.
func SetTapAllow(prefixes []netip.Prefix) error {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	if err := loadTapLocked(); err != nil {
		return err
	}
	for _, name := range []string{"allow4", "allow6"} {
		m := tapMgr.coll.Maps[name]
		var keys4 []lpm4Key
		var keys6 []lpm6Key
		var k4 lpm4Key
		var k6 lpm6Key
		var v uint8
		it := m.Iterate()
		if name == "allow4" {
			for it.Next(&k4, &v) {
				keys4 = append(keys4, k4)
			}
			for _, k := range keys4 {
				_ = m.Delete(k)
			}
		} else {
			for it.Next(&k6, &v) {
				keys6 = append(keys6, k6)
			}
			for _, k := range keys6 {
				_ = m.Delete(k)
			}
		}
	}
	for _, p := range prefixes {
		a := p.Addr().Unmap()
		if a.Is4() {
			bits := p.Bits()
			if p.Addr().Is4In6() {
				bits -= 96
			}
			if err := tapMgr.coll.Maps["allow4"].Put(lpm4Key{Prefixlen: uint32(bits), Addr: a.As4()}, uint8(1)); err != nil {
				return err
			}
			continue
		}
		if err := tapMgr.coll.Maps["allow6"].Put(lpm6Key{Prefixlen: uint32(p.Bits()), Addr: a.As16()}, uint8(1)); err != nil {
			return err
		}
	}
	return nil
}

// TapStats sums each tap's per-CPU counters, keyed by interface index.
func TapStats() map[uint32]TapStat {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	out := map[uint32]TapStat{}
	if tapMgr.coll == nil {
		return out
	}
	var idx uint32
	var per []tapStatC
	it := tapMgr.coll.Maps["tap_stats"].Iterate()
	for it.Next(&idx, &per) {
		var s TapStat
		for _, c := range per {
			s.FromPkts += c.FromPkts
			s.FromBytes += c.FromBytes
			s.ToPkts += c.ToPkts
			s.ToBytes += c.ToBytes
			s.DroppedPkts += c.DroppedPkts
			s.DroppedBytes += c.DroppedBytes
		}
		out[idx] = s
	}
	return out
}

// SetTapDNS turns DNS name events on or off in the kernel program. The switch lives in a pinned map so
// it is the same for the program that is already attached, and the daemon sets it on every start:
// what a previous run left there is never assumed. With it off the program does not look at DNS at all.
func SetTapDNS(on bool) error {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	if err := loadTapLocked(); err != nil {
		return err
	}
	m := tapMgr.coll.Maps["dns_cfg"]
	if m == nil {
		return errors.New("the tap program has no dns_cfg map")
	}
	var off uint32
	if !on {
		off = 1
	}
	return m.Put(uint32(0), off)
}

// SetTapTLS turns TLS server name events on or off in the kernel program, as SetTapDNS does for DNS names.
// With it off the program does not read a TCP payload at all. A program from before TLS names has no such
// map, which is reported and is not a failure of anything else.
func SetTapTLS(on bool) error {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	if err := loadTapLocked(); err != nil {
		return err
	}
	m := tapMgr.coll.Maps["tls_cfg"]
	if m == nil {
		return errors.New("the tap program has no tls_cfg map")
	}
	var off uint32
	if !on {
		off = 1
	}
	return m.Put(uint32(0), off)
}
