package persist

import (
	"errors"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/zyvorai/shukra/internal/state"
)

const (
	actionsFile = "actions.jsonl"
	incidentDir = "incidents"
	// maxIncidents is how many incident bundles are kept on disk, newest first.
	maxIncidents = 200
)

var validID = regexp.MustCompile(`^a-[0-9]{1,9}$`)

// Actions keeps what the response engine decided, and the incident bundle each decision was made on. It
// implements response.Store. The files are private: they name VMs, addresses and DNS names.
type Actions struct {
	log *Log
	dir string
}

// OpenActions opens the action log under dir and returns what it holds, oldest first (the last record of an
// id is the truth: the engine reads it that way).
func OpenActions(dir string) (*Actions, []state.Action, error) {
	past, err := ReadTail[state.Action](filepath.Join(dir, actionsFile), 2000)
	if err != nil {
		log.Printf("persist: reading %s: %v", actionsFile, err)
	}
	l, err := OpenLog(filepath.Join(dir, actionsFile), DefaultMaxBytes)
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(filepath.Join(dir, incidentDir), 0o700); err != nil {
		l.Close()
		return nil, nil, err
	}
	return &Actions{log: l, dir: dir}, past, nil
}

// Close closes the log.
func (a *Actions) Close() error { return a.log.Close() }

// Append implements response.Store.
func (a *Actions) Append(x state.Action) error { return a.log.Append(x) }

func (a *Actions) bundlePath(id string) (string, bool) {
	if !validID.MatchString(id) { // an id comes from a URL: it must not name a path
		return "", false
	}
	return filepath.Join(a.dir, incidentDir, id+".json"), true
}

// SaveBundle implements response.Store. It keeps the newest maxIncidents files.
func (a *Actions) SaveBundle(id string, b []byte) error {
	p, ok := a.bundlePath(id)
	if !ok {
		return errors.New("not an action id")
	}
	if err := os.WriteFile(p, b, 0o600); err != nil {
		return err
	}
	a.prune()
	return nil
}

// LoadBundle implements response.Store.
func (a *Actions) LoadBundle(id string) ([]byte, bool) {
	p, ok := a.bundlePath(id)
	if !ok {
		return nil, false
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, false
	}
	return b, true
}

func (a *Actions) prune() {
	entries, err := os.ReadDir(filepath.Join(a.dir, incidentDir))
	if err != nil || len(entries) <= maxIncidents {
		return
	}
	type f struct {
		name string
		n    int
	}
	var files []f
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		id := strings.TrimSuffix(e.Name(), ".json")
		if !validID.MatchString(id) {
			continue
		}
		var n int
		for _, c := range id[2:] {
			n = n*10 + int(c-'0')
		}
		files = append(files, f{e.Name(), n})
	}
	sort.Slice(files, func(i, j int) bool { return files[i].n < files[j].n })
	for len(files) > maxIncidents {
		if err := os.Remove(filepath.Join(a.dir, incidentDir, files[0].name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return
		}
		files = files[1:]
	}
}
