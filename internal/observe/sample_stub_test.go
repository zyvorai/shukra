//go:build !shukrabpf

package observe

import "testing"

func TestSampleStubIsNil(t *testing.T) {
	if Sample() != nil {
		t.Fatal("stub build invented counters")
	}
}
