// Package hist turns a log2 latency histogram into percentile estimates.
// Bucket i covers [1<<i, 1<<(i+1)) nanoseconds. Bucket 0 also covers 0.
package hist

import "math/bits"

const Buckets = 64

// Bucket maps a latency in nanoseconds to a log2 slot.
func Bucket(ns uint64) int {
	if ns == 0 {
		return 0
	}
	b := bits.Len64(ns) - 1
	if b >= Buckets {
		return Buckets - 1
	}
	return b
}

// Percentile returns the high edge of the bucket where the cumulative
// count first reaches p (0–100). An empty histogram returns 0.
func Percentile(counts []uint64, p float64) uint64 {
	if p < 0 {
		p = 0
	}
	if p > 100 {
		p = 100
	}
	var total uint64
	for _, c := range counts {
		total += c
	}
	if total == 0 {
		return 0
	}
	target := uint64(float64(total)*p/100 + 0.999999)
	if target == 0 {
		target = 1
	}
	var cum uint64
	for i, c := range counts {
		cum += c
		if cum >= target {
			return edge(i)
		}
	}
	return edge(len(counts) - 1)
}

func edge(bucket int) uint64 {
	if bucket < 0 {
		return 0
	}
	if bucket >= 63 {
		return 1<<63 - 1
	}
	return 1 << (bucket + 1)
}
