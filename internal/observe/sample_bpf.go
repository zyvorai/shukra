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
	}
	out := make(map[uint32]aggregate.Counters, len(by))
	for pid, c := range by {
		out[pid] = *c
	}
	return out
}

func slot(by map[uint32]*aggregate.Counters, pid uint32) *aggregate.Counters {
	c := by[pid]
	if c == nil {
		c = &aggregate.Counters{}
		by[pid] = c
	}
	return c
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
	readU32(maps["kvm_entries"], func(pid uint32, v uint64) { slot(by, pid).Entries += v })
	readU32(maps["kvm_mmio"], func(pid uint32, v uint64) { slot(by, pid).MMIO += v })
	readU32(maps["kvm_pio"], func(pid uint32, v uint64) { slot(by, pid).PIO += v })
}

func readSched(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	m := maps["sched_stats"]
	if m == nil {
		return
	}
	var pid uint32
	var val struct {
		OnCPU       uint64
		WakeupDelay uint64
		WakeupCount uint64
		LastOn      uint64
	}
	it := m.Iterate()
	for it.Next(&pid, &val) {
		c := slot(by, pid)
		c.OnCPUNs += val.OnCPU
		c.WakeupDelayNs += val.WakeupDelay
		c.WakeupCount += val.WakeupCount
	}
	readHist2(maps["sched_hist"], func(c *aggregate.Counters) *[]uint64 { return &c.SchedHist }, by)
}

// readHist2 reads a map keyed by {u32 pid, u32 bucket} into a log2 histogram.
func readHist2(m *ebpf.Map, dst func(*aggregate.Counters) *[]uint64, by map[uint32]*aggregate.Counters) {
	if m == nil {
		return
	}
	var key struct{ Pid, Bucket uint32 }
	var val uint64
	it := m.Iterate()
	for it.Next(&key, &val) {
		h := dst(slot(by, key.Pid))
		if *h == nil {
			*h = make([]uint64, hist.Buckets)
		}
		if int(key.Bucket) < len(*h) {
			(*h)[key.Bucket] += val
		}
	}
}

// SetWatched tells the sched program which tgids are QEMU processes, so exec and
// exit events are only emitted for them and their children. It adds the missing
// ones and removes the ones that are gone.
func SetWatched(tgids []uint32) {
	for _, live := range bpfgen.Collections() {
		if live.Coll == nil || live.Name != "sched" {
			continue
		}
		m := live.Coll.Maps["watched"]
		if m == nil {
			return
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
		var val struct{ Ops, Bytes, MaxNs uint64 }
		it := m.Iterate()
		for it.Next(&key, &val) {
			c := slot(by, key.Pid)
			if key.Write != 0 {
				c.BlockWriteOps += val.Ops
				c.BlockWriteBytes += val.Bytes
				c.BlockWriteMax = max(c.BlockWriteMax, val.MaxNs)
			} else {
				c.BlockReadOps += val.Ops
				c.BlockReadBytes += val.Bytes
				c.BlockReadMax = max(c.BlockReadMax, val.MaxNs)
			}
		}
	}
}

func readRetrans(by map[uint32]*aggregate.Counters, maps map[string]*ebpf.Map) {
	readU32(maps["net_retrans"], func(pid uint32, v uint64) { slot(by, pid).Retransmits += v })
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
