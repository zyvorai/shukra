// Package sink delivers detections somewhere an operator will see them.
// Delivery is asynchronous and lossy by design: the event path never waits on a
// slow webhook. A detection that cannot be delivered is counted, not retried
// forever, and the same detection is still in the API and the persisted log.
package sink

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

// QueueSize is how many detections wait for each sink before new ones are dropped.
const QueueSize = 256

// Sink is one destination for detections.
type Sink interface {
	Name() string
	// Send delivers one detection. It should honor ctx, which is cancelled at
	// shutdown so a retrying sink does not hold the daemon open.
	Send(ctx context.Context, e event.Event) error
	Close() error
}

type entry struct {
	s       Sink
	q       chan event.Event
	sent    atomic.Uint64
	failed  atomic.Uint64
	dropped atomic.Uint64
}

// Dispatcher fans each detection out to every sink. Each sink has its own queue
// and goroutine, so a stuck webhook cannot delay the file or syslog sink.
type Dispatcher struct {
	entries []*entry
	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	mu      sync.RWMutex
	closed  bool
}

// NewDispatcher starts one worker per sink.
func NewDispatcher(sinks ...Sink) *Dispatcher {
	ctx, cancel := context.WithCancel(context.Background())
	d := &Dispatcher{ctx: ctx, cancel: cancel}
	for _, s := range sinks {
		en := &entry{s: s, q: make(chan event.Event, QueueSize)}
		d.entries = append(d.entries, en)
		d.wg.Add(1)
		go d.run(en)
	}
	return d
}

func (d *Dispatcher) run(en *entry) {
	defer d.wg.Done()
	for e := range en.q {
		if err := en.s.Send(d.ctx, e); err != nil {
			en.failed.Add(1)
			log.Printf("sink %s: delivering %q failed: %v", en.s.Name(), e.Rule, err)
			continue
		}
		en.sent.Add(1)
	}
}

// Emit queues e for every sink and returns at once. It matches the signature
// state.OnDetection wants. A full queue drops the detection for that sink.
func (d *Dispatcher) Emit(e event.Event) {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.closed {
		return
	}
	for _, en := range d.entries {
		select {
		case en.q <- e:
		default:
			en.dropped.Add(1)
		}
	}
}

// Stats is delivery accounting per sink, in the order they were given.
func (d *Dispatcher) Stats() []state.SinkStat {
	out := make([]state.SinkStat, 0, len(d.entries))
	for _, en := range d.entries {
		out = append(out, state.SinkStat{
			Name: en.s.Name(), Sent: en.sent.Load(), Failed: en.failed.Load(), Dropped: en.dropped.Load(),
		})
	}
	return out
}

// Close stops accepting detections, gives the queues up to grace to drain, then
// cancels anything still retrying and closes the sinks.
func (d *Dispatcher) Close(grace time.Duration) {
	d.mu.Lock()
	if d.closed {
		d.mu.Unlock()
		return
	}
	d.closed = true
	for _, en := range d.entries {
		close(en.q)
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() { d.wg.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(grace):
		d.cancel()
		<-done
	}
	d.cancel()
	for _, en := range d.entries {
		if err := en.s.Close(); err != nil {
			log.Printf("sink %s: close: %v", en.s.Name(), err)
		}
	}
}
