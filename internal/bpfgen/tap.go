//go:build linux && shukrabpf

package bpfgen

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

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

// The tap program is not attached once at start like the others: it goes on each
// VM's tap as VMs appear and comes off as they go. This is the one place that
// knows which interfaces have it.
var tapMgr struct {
	mu      sync.Mutex
	loaded  bool
	loadErr error
	coll    *ebpf.Collection
	taps    map[string]*tapLinks
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
	coll, err := ebpf.NewCollection(spec)
	if err != nil {
		tapMgr.loadErr = fmt.Errorf("loading the tap program: %w", err)
		return tapMgr.loadErr
	}
	tapMgr.coll = coll
	return nil
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

func attachTapLocked(name string, ifindex uint32) error {
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
	tapMgr.taps[name] = &tapLinks{ifindex: ifindex, in: in, out: out}
	return nil
}

func detachTapLocked(name string) {
	t := tapMgr.taps[name]
	if t == nil {
		return
	}
	_ = t.in.Close()
	_ = t.out.Close()
	_ = tapMgr.coll.Maps["tap_policy"].Delete(t.ifindex)
	delete(tapMgr.taps, name)
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
