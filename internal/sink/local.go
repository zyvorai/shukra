package sink

import (
	"context"
	"encoding/json"
	"log/syslog"

	"github.com/zyvorai/shukra/internal/event"
	"github.com/zyvorai/shukra/internal/persist"
)

// File appends each detection as a JSON line, rolling at persist.DefaultMaxBytes.
type File struct{ log *persist.Log }

// NewFile opens path for appending with mode 0600.
func NewFile(path string) (*File, error) {
	l, err := persist.OpenLog(path, persist.DefaultMaxBytes)
	if err != nil {
		return nil, err
	}
	return &File{log: l}, nil
}

func (f *File) Name() string                                { return "file" }
func (f *File) Send(_ context.Context, e event.Event) error { return f.log.Append(e) }
func (f *File) Close() error                                { return f.log.Close() }

// syslogWriter is the part of *syslog.Writer the sink uses.
type syslogWriter interface {
	Crit(string) error
	Err(string) error
	Warning(string) error
	Notice(string) error
	Close() error
}

// Syslog writes each detection as one JSON line to the local syslog daemon.
// Severity maps critical to crit, high to err, medium to warning, low to notice.
type Syslog struct{ w syslogWriter }

// NewSyslog connects to the local syslog daemon as facility daemon, tag "shukra".
func NewSyslog() (*Syslog, error) {
	w, err := syslog.New(syslog.LOG_DAEMON|syslog.LOG_WARNING, "shukra")
	if err != nil {
		return nil, err
	}
	return &Syslog{w: w}, nil
}

func (s *Syslog) Name() string { return "syslog" }
func (s *Syslog) Close() error { return s.w.Close() }

func (s *Syslog) Send(_ context.Context, e event.Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	switch e.Severity {
	case "critical":
		return s.w.Crit(string(b))
	case "high":
		return s.w.Err(string(b))
	case "low":
		return s.w.Notice(string(b))
	default:
		return s.w.Warning(string(b))
	}
}
