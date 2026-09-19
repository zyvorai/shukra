package hist

import "testing"

func TestPercentile(t *testing.T) {
	counts := make([]uint64, Buckets)
	// 100 samples in bucket 10: [1024, 2048)
	counts[10] = 50
	counts[20] = 50
	p50 := Percentile(counts, 50)
	p99 := Percentile(counts, 99)
	if p50 != 1<<11 {
		t.Fatalf("p50 %d", p50)
	}
	if p99 != 1<<21 {
		t.Fatalf("p99 %d", p99)
	}
	if Percentile(nil, 99) != 0 {
		t.Fatal("empty")
	}
}

func TestBucket(t *testing.T) {
	if Bucket(0) != 0 || Bucket(1) != 0 || Bucket(2) != 1 || Bucket(1024) != 10 {
		t.Fatalf("buckets %d %d %d", Bucket(1), Bucket(2), Bucket(1024))
	}
}
