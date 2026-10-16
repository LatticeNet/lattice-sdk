package model

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// eachIndex calls fn(i) for every i in [0, n), spread over up to GOMAXPROCS
// workers (at most eight) once n is large enough to repay starting them,
// and returns when every call has returned. fn must touch only what index
// i owns.
func eachIndex(n int, fn func(i int)) {
	workers := min(runtime.GOMAXPROCS(0), 8)
	if n < 128 || workers < 2 {
		for i := 0; i < n; i++ {
			fn(i)
		}
		return
	}
	const block = 32
	var next atomic.Int64
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				start := int(next.Add(block)) - block
				if start >= n {
					return
				}
				for i := start; i < min(start+block, n); i++ {
					fn(i)
				}
			}
		}()
	}
	wg.Wait()
}
