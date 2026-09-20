package persist

import (
	"log"
	"path/filepath"
	"time"

	"github.com/zyvorai/shukra/internal/baseline"
)

const baselinesFile = "baselines.json"

// LoadBaselines restores what was learned into s. A missing file is a first run; a file that does not parse is
// logged and ignored, so a damaged file costs the learning, never the daemon.
func LoadBaselines(dir string, s *baseline.Store) {
	d, err := ReadJSON[baseline.Data](filepath.Join(dir, baselinesFile))
	if err != nil {
		log.Printf("persist: reading %s: %v (learning starts over)", baselinesFile, err)
		return
	}
	s.Restore(d)
	if n := len(s.Status("", time.Now())); n > 0 {
		log.Printf("persist: restored the baselines of %d VMs from %s", n, dir)
	}
}

// SaveBaselines writes what has been learned, if it changed since the last save. The file is private: it lists
// the networks and names each VM talks to.
func SaveBaselines(dir string, s *baseline.Store) error {
	d, changed := s.Snapshot()
	if !changed {
		return nil
	}
	return WriteJSON(filepath.Join(dir, baselinesFile), d)
}
