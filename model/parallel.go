package model

import (
	"runtime"
	"sync"
	"sync/atomic"
)

// eachIndex calls fn(i) for every i in [0, n), spread over up to GOMAXPROCS
// workers (at most eight, the calling goroutine one of them) once n is large
// enough to repay starting them, and returns when every call has returned.
// fn must touch only what index i owns.
//
// A panic in fn reaches the caller as it would from a plain loop: the worker
// that panicked recovers, the others stop taking indexes, and once all have
// returned eachIndex panics again on the calling goroutine with the first
// value, so the caller's own recover (a plugin runtime's per-invocation one)
// still applies. A panic left on a worker goroutine would end the process.
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
	var first atomic.Pointer[workerPanic]
	work := func() {
		defer func() {
			if v := recover(); v != nil {
				first.CompareAndSwap(nil, &workerPanic{value: v})
				next.Store(int64(n))
			}
		}()
		for {
			start := int(next.Add(block)) - block
			if start >= n {
				return
			}
			for i := start; i < min(start+block, n); i++ {
				fn(i)
			}
		}
	}
	var wg sync.WaitGroup
	for w := 1; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			work()
		}()
	}
	work()
	wg.Wait()
	if p := first.Load(); p != nil {
		panic(p.value)
	}
}

// workerPanic carries a recovered panic value from a worker to the caller.
type workerPanic struct{ value any }
