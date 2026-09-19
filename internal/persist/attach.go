package persist

import (
	"log"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/state"
)

const (
	detectionsFile = "detections.jsonl"
	isolationsFile = "isolations.jsonl"
	recorderFile   = "recorder.json"
)

// Handle is a state.Persister backed by files under one directory.
type Handle struct {
	st      *state.State
	dir     string
	det     *Log
	iso     *Log
	failing atomic.Bool
}

// Attach restores what a previous run saved into st and then starts writing new
// detections and isolations to dir. dir is created with mode 0700 if needed. A
// corrupt file loses its bad lines, and never blocks startup.
func Attach(st *state.State, dir string) (*Handle, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	h := &Handle{st: st, dir: dir}

	dets, err := ReadTail[event.Event](filepath.Join(dir, detectionsFile), state.MaxEvents)
	if err != nil {
		log.Printf("persist: reading %s: %v", detectionsFile, err)
	}
	isos, err := ReadTail[state.Isolation](filepath.Join(dir, isolationsFile), state.MaxEvents)
	if err != nil {
		log.Printf("persist: reading %s: %v", isolationsFile, err)
	}
	rec, err := ReadJSON[[]event.Event](filepath.Join(dir, recorderFile))
	if err != nil {
		log.Printf("persist: reading %s: %v", recorderFile, err)
	}
	st.Restore(dets, isos, rec)
	log.Printf("persist: restored %d detections, %d isolations, %d recorder events from %s", len(dets), len(isos), len(rec), dir)

	if h.det, err = OpenLog(filepath.Join(dir, detectionsFile), DefaultMaxBytes); err != nil {
		return nil, err
	}
	if h.iso, err = OpenLog(filepath.Join(dir, isolationsFile), DefaultMaxBytes); err != nil {
		h.det.Close()
		return nil, err
	}
	st.SetPersister(h)
	return h, nil
}

// Detection implements state.Persister.
func (h *Handle) Detection(e event.Event) { h.report(h.det.Append(e), detectionsFile) }

// Isolation implements state.Persister.
func (h *Handle) Isolation(i state.Isolation) { h.report(h.iso.Append(i), isolationsFile) }

// report logs the first failure and the recovery, not every failed write, so a
// full disk during a detection storm does not also flood the journal.
func (h *Handle) report(err error, what string) {
	switch {
	case err != nil && h.failing.CompareAndSwap(false, true):
		log.Printf("persist: writing %s failed, will keep trying: %v", what, err)
	case err == nil && h.failing.CompareAndSwap(true, false):
		log.Printf("persist: writing %s works again", what)
	}
}

// Snapshot saves the flight recorder. It is not written per event.
func (h *Handle) Snapshot() error {
	return WriteJSON(filepath.Join(h.dir, recorderFile), h.st.RecorderSnapshot())
}

// Close saves a final snapshot and closes the logs.
func (h *Handle) Close() error {
	h.st.SetPersister(nil)
	err := h.Snapshot()
	if e := h.det.Close(); err == nil {
		err = e
	}
	if e := h.iso.Close(); err == nil {
		err = e
	}
	return err
}
