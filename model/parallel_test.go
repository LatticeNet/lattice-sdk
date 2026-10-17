package model

import (
	"sync/atomic"
	"testing"
)

// A panic in fn on a worker reaches the caller, where its recover sees it,
// instead of ending the process; below the parallel threshold it is a plain
// loop's panic.
func TestEachIndexPanicsOnTheCaller(t *testing.T) {
	for _, n := range []int{10, 128, 4096} {
		for _, at := range []int{0, n / 2, n - 1} {
			got := func() (v any) {
				defer func() { v = recover() }()
				eachIndex(n, func(i int) {
					if i == at {
						panic("boom")
					}
				})
				return nil
			}()
			if got != "boom" {
				t.Fatalf("n=%d, panic at %d: the caller recovered %v", n, at, got)
			}
		}
	}
}

func TestEachIndexCallsEveryIndexOnce(t *testing.T) {
	for _, n := range []int{0, 1, 127, 128, 129, 4097} {
		calls := make([]atomic.Int32, n)
		eachIndex(n, func(i int) { calls[i].Add(1) })
		for i := range calls {
			if c := calls[i].Load(); c != 1 {
				t.Fatalf("n=%d: index %d called %d times", n, i, c)
			}
		}
	}
}
