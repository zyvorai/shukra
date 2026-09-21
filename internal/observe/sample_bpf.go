//go:build linux && shukrabpf

package observe

import (
	"errors"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/zyvorai/shukra/internal/aggregate"
	"github.com/zyvorai/shukra/internal/bpfgen"
	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/hist"
)

var lost atomic.Uint64

func lostSamples() uint64 { return lost.Load() }

// Sample reads the pinned maps. An empty map means the hooks are quiet, not
// that counters were invented. Nil is reserved for the stub build.
func Sample() map[uint32]aggregate.Counters {
	by := map[uint32]*aggregate.Counters{}
	for _, live := range bpfgen.Collections() {
		if live.Coll == nil {
			continue
		}
		readKVM(by, live.Coll.Maps)
		readSched(by, live.Coll.Maps)
		readBlock(by, live.Coll.Maps)
		readRetrans(by, live.Coll.Maps)
		readMemory(by, live.Coll.Maps)
	}
	out := make(map[uint32]aggregate.Counters, len(by))
	for pid, c := range by {
		out[pid] = *c
	}
	return out
}

func readKVM(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	if m := maps["kvm_exits"]; m != nil {
		var key struct {
			Pid    uint32
			Reason uint32
		}
		var val uint64
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			if c.Exits == nil {
				c.Exits = map[uint32]uint64{}
			}
			c.Exits[key.Reason] += val
		}
	}
	if m := maps["kvm_reason_ns"]; m != nil {
		var key struct{ Pid, Reason uint32 }
		var val uint64
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			if c.ExitNs == nil {
				c.ExitNs = map[uint32]uint64{}
			}
			c.ExitNs[key.Reason] += val
		}
	}
	readHist2(maps["kvm_lat"], func(c *aggregate.Counters) *[]uint64 { return &c.KVMLat }, by, slot)
	readU32(maps["kvm_entries"], func(pid uint32, v uint64) { slot(by, pid).Entries += v })
	readU32(maps["kvm_mmio"], func(pid uint32, v uint64) { slot(by, pid).MMIO += v })
	readU32(maps["kvm_pio"], func(pid uint32, v uint64) { slot(by, pid).PIO += v })
}

func readSched(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	m := maps["sched_stats"]
	if m == nil {
		return
	}
	type schedVal struct {
		OnCPU        uint64
		WakeupDelay  uint64
		WakeupCount  uint64
		LastOn       uint64
		PreemptNs    uint64
		PreemptCount uint64
	}
	forEach(m, func(pid uint32, val schedVal) {
		c := schedSlot(by, pid)
		c.OnCPUNs += val.OnCPU
		c.WakeupDelayNs += val.WakeupDelay
		c.WakeupCount += val.WakeupCount
		// Only a vCPU thread's wait is preemption of the guest's CPU. An iothread that waited for a host CPU
		// is not the guest losing its processor, and a thread that no VM owns is not counted at all.
		if r, ok := threadRef(pid); ok && r.Role == "vcpu" {
			c.PreemptNs += val.PreemptNs
			c.PreemptCount += val.PreemptCount
		}
	})
	readHist2(maps["sched_hist"], func(c *aggregate.Counters) *[]uint64 { return &c.SchedHist }, by, schedSlot)
	readPreemptors(by, maps["preempt_by"])
}

// readPreemptors reads who took the CPU of each preempted vCPU thread.
func readPreemptors(by map[uint32]*aggregate.Counters, m *ebpf.Map) {
	if m == nil {
		return
	}
	type key struct{ Victim, By uint32 }
	type val struct {
		Count, Ns uint64
		Comm      [16]byte
	}
	forEach(m, func(k key, v val) {
		if r, ok := threadRef(k.Victim); !ok || r.Role != "vcpu" {
			return
		}
		c := slot(by, k.Victim)
		if c.Preemptors == nil {
			c.Preemptors = map[string]uint64{}
		}
		c.Preemptors[preemptorLabel(k.By, commString(v.Comm), threadRef)] += v.Ns
	})
}

// readHist2 reads a map keyed by {u32 pid, u32 bucket} into a log2 histogram.
func readHist2(m *ebpf.Map, dst func(*aggregate.Counters) *[]uint64, by map[uint32]*aggregate.Counters, slotFor func(map[uint32]*aggregate.Counters, uint32) *aggregate.Counters) {
	if m == nil {
		return
	}
	type key struct{ Pid, Bucket uint32 }
	forEach(m, func(k key, v uint64) {
		h := dst(slotFor(by, k.Pid))
		if *h == nil {
			*h = make([]uint64, hist.Buckets)
		}
		if int(k.Bucket) < len(*h) {
			(*h)[k.Bucket] += v
		}
	})
}

// forEach calls f for every entry of m. It reads in batches, one system call for up to a couple of thousand
// entries, where walking the map with get-next-key costs two per entry: on a host with tens of thousands of
// threads that was over two hundred thousand system calls every refresh. A kernel or map that cannot batch
// is walked the slow way, and an entry that is deleted while the map is read is no reason to stop.
func forEach[K, V any](m *ebpf.Map, f func(K, V)) {
	const batch = 2048
	keys := make([]K, batch)
	vals := make([]V, batch)
	var cur ebpf.MapBatchCursor
	seen := 0
	for {
		n, err := m.BatchLookup(&cur, keys, vals, nil)
		for i := 0; i < n; i++ {
			f(keys[i], vals[i])
		}
		seen += n
		switch {
		case err == nil:
			continue
		case errors.Is(err, ebpf.ErrKeyNotExist):
			return // the whole map has been read
		case seen == 0:
			// Batching is not available here (an older kernel, or a map type that has no batch): nothing has
			// been given to f yet, so the whole map can still be read the other way.
			var k K
			var v V
			for it := m.Iterate(); it.Next(&k, &v); {
				f(k, v)
			}
			return
		default:
			return // the rest is read on the next refresh; counters only go up, so nothing is lost
		}
	}
}

// SetWatched tells the sched program which tgids are QEMU processes, so exec and
// exit events are only emitted for them and their children, and the vmm program the
// same, so that only they are watched for the calls a VMM has no business making.
// It adds the missing ones and removes the ones that are gone.
func SetWatched(tgids []uint32) {
	for _, live := range bpfgen.Collections() {
		if live.Coll == nil {
			continue
		}
		var m *ebpf.Map
		switch live.Name {
		case "sched":
			m = live.Coll.Maps["watched"]
		case "vmm":
			m = live.Coll.Maps["vmm_watched"]
		}
		if m == nil {
			continue
		}
		want := make(map[uint32]bool, len(tgids))
		for _, t := range tgids {
			want[t] = true
			_ = m.Put(t, uint8(1))
		}
		var have []uint32
		var k uint32
		var v uint8
		it := m.Iterate()
		for it.Next(&k, &v) {
			if !want[k] {
				have = append(have, k)
			}
		}
		for _, k := range have {
			_ = m.Delete(k)
		}
	}
}

func readBlock(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	if m := maps["blk_hist"]; m != nil {
		var key struct {
			Pid    uint32
			Write  uint8
			Bucket uint8
			_      [2]byte
		}
		var val uint64
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			dst := &c.BlockRead
			if key.Write != 0 {
				dst = &c.BlockWrite
			}
			if *dst == nil {
				*dst = make([]uint64, hist.Buckets)
			}
			if int(key.Bucket) < len(*dst) {
				(*dst)[key.Bucket] += val
			}
		}
	}
	readU32(maps["blk_issues"], func(pid uint32, v uint64) { slot(by, pid).BlockIssues += v })
	if m := maps["blk_io"]; m != nil {
		var key struct{ Pid, Write uint32 }
		var val struct{ Ops, Bytes, MaxNs, Errors uint64 }
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			if key.Write != 0 {
				c.BlockWriteOps += val.Ops
				c.BlockWriteBytes += val.Bytes
				c.BlockWriteMax = max(c.BlockWriteMax, val.MaxNs)
				c.BlockWriteErrors += val.Errors
			} else {
				c.BlockReadOps += val.Ops
				c.BlockReadBytes += val.Bytes
				c.BlockReadMax = max(c.BlockReadMax, val.MaxNs)
				c.BlockReadErrors += val.Errors
			}
		}
	}
	if m := maps["blk_qhist"]; m != nil {
		var key struct {
			Pid    uint32
			Write  uint8
			Bucket uint8
			_      [2]byte
		}
		var val uint64
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			dst := &c.BlockQRead
			if key.Write != 0 {
				dst = &c.BlockQWrite
			}
			if *dst == nil {
				*dst = make([]uint64, hist.Buckets)
			}
			if int(key.Bucket) < len(*dst) {
				(*dst)[key.Bucket] += val
			}
		}
	}
}

func readRetrans(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	readU32(maps["net_retrans"], func(pid uint32, v uint64) { slot(by, pid).Retransmits += v })
	readU32(maps["net_connects"], func(pid uint32, v uint64) { slot(by, pid).Connects += v })
}

func readMemory(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	readHist2(maps["reclaim_hist"], func(c *aggregate.Counters) *[]uint64 { return &c.ReclaimHist }, by, slot)
	readU32(maps["reclaim_ns"], func(pid uint32, v uint64) { slot(by, pid).ReclaimNs += v })
	readU32(maps["reclaim_count"], func(pid uint32, v uint64) { slot(by, pid).ReclaimCount += v })
	readU32(maps["oom_kills"], func(pid uint32, v uint64) { slot(by, pid).OOMKills += v })
}

func readU32(m *ebpf.Map, fn func(pid uint32, v uint64)) {
	if m == nil {
		return
	}
	var pid uint32
	var val uint64
	it := m.Iterate()
	for it.Next(&pid, &val) {
		fn(pid, val)
	}
}

var startOnce sync.Once

// Start reads every events ring once. Connect totals are not in a map; the
// agent counts them from the events this delivers.
func Start(handler func(event.Event)) {
	startOnce.Do(func() {
		if handler == nil {
			return
		}
		for _, live := range bpfgen.Collections() {
			if live.Coll == nil {
				continue
			}
			m := live.Coll.Maps["events"]
			if m == nil || m.Type() != ebpf.RingBuf {
				continue
			}
			rd, err := ringbuf.NewReader(m)
			if err != nil {
				lost.Add(1)
				continue
			}
			go readRing(rd, handler)
		}
	})
}

func readRing(rd *ringbuf.Reader, handler func(event.Event)) {
	var rec ringbuf.Record
	for {
		err := rd.ReadInto(&rec)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			lost.Add(1)
			time.Sleep(50 * time.Millisecond)
			continue
		}
		raw := append([]byte(nil), rec.RawSample...)
		ev, ok := DecodeRing(raw)
		if !ok {
			lost.Add(1)
			continue
		}
		handler(ev)
	}
}
