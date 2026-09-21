// Package persist keeps the records worth surviving a restart: detections,
// isolation requests, and a flight-recorder snapshot. Files are JSON, one record
// per line for the logs. Nothing here is a source of truth for counters.
package persist

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
)

// DefaultMaxBytes is the size at which a log rolls to path+".1".
const DefaultMaxBytes = 16 << 20

// Log is an append-only JSON-lines file. When it would pass maxBytes it moves to
// path+".1", replacing any older one, so disk use stays near twice maxBytes.
type Log struct {
	mu   sync.Mutex
	path string
	max  int64
	f    *os.File
	size int64
}

// OpenLog opens path for appending, creating it with mode 0600.
func OpenLog(path string, maxBytes int64) (*Log, error) {
	l := &Log{path: path, max: maxBytes}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) open() error {
	f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, fi.Size()
	// A crash can leave a torn last line. End it so the next record starts clean.
	if l.size > 0 {
		var last [1]byte
		if rf, err := os.Open(l.path); err == nil {
			_, rerr := rf.ReadAt(last[:], l.size-1)
			rf.Close()
			if rerr == nil && last[0] != '\n' {
				n, _ := l.f.Write([]byte{'\n'})
				l.size += int64(n)
			}
		}
	}
	return nil
}

// Append writes v as one line.
func (l *Log) Append(v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return os.ErrClosed
	}
	if l.max > 0 && l.size > 0 && l.size+int64(len(b)) > l.max {
		// A failed rotation is retried on the next append. Keep writing to the
		// current file rather than drop a detection, unless it cannot be reopened.
		if err := l.rotate(); err != nil && l.f == nil {
			return err
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	return err
}

// Sync flushes the log to stable storage. Close also syncs.
func (l *Log) Sync() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return os.ErrClosed
	}
	return l.f.Sync()
}

func (l *Log) rotate() error {
	_ = l.f.Close()
	renameErr := os.Rename(l.path, l.path+".1")
	if err := l.open(); err != nil {
		l.f = nil
		return err
	}
	return renameErr
}

// Close syncs and closes the file.
func (l *Log) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Sync()
	if cerr := l.f.Close(); err == nil {
		err = cerr
	}
	l.f = nil
	return err
}

// ReadTail returns the newest n records from path.1 and path, oldest first. A
// line that does not decode is skipped, since a crash can tear the last one.
// On a read error it returns what it has along with the error.
func ReadTail[T any](path string, n int) ([]T, error) {
	var lines [][]byte
	var rerr error
	for _, p := range []string{path + ".1", path} {
		f, err := os.Open(p)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			rerr = err
			continue
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for sc.Scan() {
			lines = append(lines, append([]byte(nil), sc.Bytes()...))
			if len(lines) > n {
				lines = lines[1:]
			}
		}
		if err := sc.Err(); err != nil {
			rerr = err
		}
		f.Close()
	}
	out := make([]T, 0, len(lines))
	for _, line := range lines {
		var v T
		if err := json.Unmarshal(line, &v); err == nil {
			out = append(out, v)
		}
	}
	return out, rerr
}

// WriteJSON replaces path with v's JSON. It writes a temp file, syncs, and
// renames, so a reader sees the old file or the new one and never half of one.
func WriteJSON(path string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFileAtomic(path, b)
}

// WriteFileAtomic replaces path with b. It syncs the file and the parent directory.
func WriteFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(b); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	return syncDir(filepath.Dir(path))
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = d.Sync()
	cerr := d.Close()
	if err != nil {
		return err
	}
	return cerr
}

// ReadJSON decodes path into T. A missing file is the zero value, not an error.
func ReadJSON[T any](path string) (T, error) {
	var v T
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return v, nil
	}
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(b, &v)
	return v, err
}
