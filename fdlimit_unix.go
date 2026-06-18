//go:build !windows

package main

import "syscall"

// raiseFDLimit raises the soft RLIMIT_NOFILE to the hard limit (best effort) and
// returns the resulting soft limit. On Unix a connect() scan is bounded by the
// per-process descriptor limit, so this headroom directly raises usable concurrency.
func raiseFDLimit() uint64 {
	var lim syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim); err != nil {
		return 1024 // conservative fallback
	}
	if lim.Cur < lim.Max {
		lim.Cur = lim.Max
		_ = syscall.Setrlimit(syscall.RLIMIT_NOFILE, &lim)
		// Re-read in case the kernel clamped the requested value.
		_ = syscall.Getrlimit(syscall.RLIMIT_NOFILE, &lim)
	}
	return lim.Cur
}
