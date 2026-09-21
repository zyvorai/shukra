package api

import (
	"strings"
	"testing"
	"time"

	"github.com/zyvorai/shukra/internal/state"
)

func TestTapAttachHistogram(t *testing.T) {
	st := state.New("h")
	st.NoteTapAttach("web", 20*time.Millisecond)
	var b strings.Builder
	writeMetrics(&b, st)
	got := b.String()
	for _, want := range []string{
		"# TYPE shukra_tap_attach_seconds histogram",
		`shukra_tap_attach_seconds_bucket{vm="web",le="0.05"} 1`,
		`shukra_tap_attach_seconds_bucket{vm="web",le="0.01"} 0`,
		`shukra_tap_attach_seconds_count{vm="web"} 1`,
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %s\n%s", want, got)
		}
	}
}
