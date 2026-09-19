//go:build linux && shukrabpf

package bpfgen

import (
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

// HandshakeBuckets is how many log2 buckets the handshake-time histogram has.
const HandshakeBuckets = 64

// tapOutcomeC mirrors struct tap_outcome in bpf/tap.bpf.c.
type tapOutcomeC struct {
	OutSyn, OutOK, OutRefused, OutRetrans, OutBlocked uint64
	InSyn, InOK, InRefused, InRetrans, InBlocked      uint64
}

// tapTimeoutC mirrors struct tap_timeout: written only by this package.
type tapTimeoutC struct {
	OutTimeout, InIgnored uint64
}

// pendKey mirrors struct pend_key in bpf/tap.bpf.c, byte for byte (44 bytes, no implicit padding).
type pendKey struct {
	Ifindex uint32
	GPort   uint16
	PPort   uint16
	Family  uint8
	Dir     uint8
	Pad     [2]uint8
	G       [16]byte
	P       [16]byte
}

// TapOutcome is what became of the TCP handshakes on one tap. Out is the guest's own connections and In
// is connections made to the guest. Out: every attempt is exactly one of Ok, Refused, Timeout or Blocked
// (or still waiting), and a repeat of the same SYN is a Retrans, not a new attempt.
type TapOutcome struct {
	OutSyn, OutOK, OutRefused, OutTimeout, OutRetrans, OutBlocked uint64
	InSyn, InOK, InRefused, InIgnored, InRetrans, InBlocked       uint64
}

// pendingMaxAge is how long a SYN may wait for an answer before it is counted as never answered. A SYN
// is retried at 1 s, 3 s, 7 s and so on, so this is well inside a client's own timeout: a slow answer
// that arrives after it is not counted as a success, and the count says a timeout.
const pendingMaxAge = 3 * time.Second

func tapOutcomeMaps() (out, hist, timeouts, pending *ebpf.Map) {
	if tapMgr.coll == nil {
		return
	}
	m := tapMgr.coll.Maps
	return m["tap_outcomes"], m["tap_handshake_hist"], m["tap_timeouts"], m["pending_syn"]
}

// monotonicNs is bpf_ktime_get_ns: CLOCK_MONOTONIC in nanoseconds.
func monotonicNs() uint64 {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return uint64(ts.Sec)*1e9 + uint64(ts.Nsec)
}

// SweepPending counts the SYNs that were never answered, and forgets them. The kernel has no timers to
// do this, so it happens when the counters are read. Only taps this daemon has attached are counted.
func SweepPending() {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	_, _, timeouts, pending := tapOutcomeMaps()
	if timeouts == nil || pending == nil {
		return
	}
	attached := map[uint32]bool{}
	for _, t := range tapMgr.taps {
		attached[t.ifindex] = true
	}
	now := monotonicNs()
	if now == 0 {
		return
	}
	var key pendKey
	var ts uint64
	var old []pendKey
	for it := pending.Iterate(); it.Next(&key, &ts); {
		if now > ts && now-ts >= uint64(pendingMaxAge) {
			old = append(old, key)
		}
	}
	for _, k := range old {
		// LookupAndDelete says whether it was still there: the program deletes a SYN the moment it is
		// answered, and one that was answered since the scan must not be counted as a timeout.
		var t0 uint64
		if err := pending.LookupAndDelete(&k, &t0); err != nil {
			continue
		}
		if !attached[k.Ifindex] {
			continue
		}
		var cur tapTimeoutC
		_ = timeouts.Lookup(k.Ifindex, &cur)
		if k.Dir == 0 {
			cur.OutTimeout++
		} else {
			cur.InIgnored++
		}
		_ = timeouts.Put(k.Ifindex, cur)
	}
}

// TapOutcomes sums each tap's per-CPU handshake counters and adds the timeouts, keyed by interface index.
func TapOutcomes() map[uint32]TapOutcome {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	out := map[uint32]TapOutcome{}
	outcomes, _, timeouts, _ := tapOutcomeMaps()
	if outcomes == nil {
		return out
	}
	var idx uint32
	var per []tapOutcomeC
	for it := outcomes.Iterate(); it.Next(&idx, &per); {
		var o TapOutcome
		for _, c := range per {
			o.OutSyn += c.OutSyn
			o.OutOK += c.OutOK
			o.OutRefused += c.OutRefused
			o.OutRetrans += c.OutRetrans
			o.OutBlocked += c.OutBlocked
			o.InSyn += c.InSyn
			o.InOK += c.InOK
			o.InRefused += c.InRefused
			o.InRetrans += c.InRetrans
			o.InBlocked += c.InBlocked
		}
		out[idx] = o
	}
	if timeouts != nil {
		var t tapTimeoutC
		for i, o := range out {
			t = tapTimeoutC{}
			if err := timeouts.Lookup(i, &t); err == nil {
				o.OutTimeout, o.InIgnored = t.OutTimeout, t.InIgnored
				out[i] = o
			}
		}
	}
	return out
}

// TapHandshakeHist is, per interface index, how long the guest's connections took to be answered, as
// HandshakeBuckets log2 buckets of nanoseconds.
func TapHandshakeHist() map[uint32][]uint64 {
	tapMgr.mu.Lock()
	defer tapMgr.mu.Unlock()
	out := map[uint32][]uint64{}
	_, hist, _, _ := tapOutcomeMaps()
	if hist == nil {
		return out
	}
	var key struct{ Ifindex, Bucket uint32 }
	var per []uint64
	for it := hist.Iterate(); it.Next(&key, &per); {
		if key.Bucket >= HandshakeBuckets {
			continue
		}
		h := out[key.Ifindex]
		if h == nil {
			h = make([]uint64, HandshakeBuckets)
			out[key.Ifindex] = h
		}
		for _, n := range per {
			h[key.Bucket] += n
		}
	}
	return out
}

// clearOutcomesLocked forgets a detached tap's handshake data, so an interface index that is reused
// never inherits another tap's history. Caller holds tapMgr.mu.
func clearOutcomesLocked(ifindex uint32) {
	outcomes, hist, timeouts, _ := tapOutcomeMaps()
	if outcomes != nil {
		_ = outcomes.Delete(ifindex)
	}
	if timeouts != nil {
		_ = timeouts.Delete(ifindex)
	}
	if hist != nil {
		for b := uint32(0); b < HandshakeBuckets; b++ {
			_ = hist.Delete(struct{ Ifindex, Bucket uint32 }{ifindex, b})
		}
	}
}
