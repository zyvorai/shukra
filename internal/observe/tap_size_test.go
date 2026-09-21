package observe

import "testing"

func TestTapRecordIs56Bytes(t *testing.T) {
	if tapEventSize != 56 {
		t.Fatalf("tap record %d", tapEventSize)
	}
}
