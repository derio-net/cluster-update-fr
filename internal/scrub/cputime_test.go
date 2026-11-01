package scrub

import (
	"syscall"
	"time"
)

// cpuTime is the process's user+system CPU time. The performance tests time
// with it, not the wall clock: on a loaded host (CI, several agents) wall
// time measures the neighbours, CPU time measures the scrubber.
func cpuTime() time.Duration {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	return time.Duration(ru.Utime.Nano() + ru.Stime.Nano())
}

// measure runs f and returns the CPU time it used.
func measure(f func()) time.Duration {
	t0 := cpuTime()
	f()
	return cpuTime() - t0
}
