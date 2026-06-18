//go:build windows

package main

// raiseFDLimit is a no-op on Windows, which has no RLIMIT_NOFILE. Windows allows a
// very large number of socket handles per process (~16M), so concurrency is not
// descriptor-bound the way it is on Unix; return a large budget so capConcurrency
// does not artificially throttle the worker pool.
func raiseFDLimit() uint64 {
	return 1 << 20 // 1,048,576
}
