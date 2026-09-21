package rls

import "sync/atomic"

// logSampler bounds a log line to a per-second budget. Refusals arrive at
// traffic speed by definition — a client hammering past its limit is the
// normal case, not the exceptional one — so the refusal log keeps at most a
// few lines per second and reports how many it dropped.
//
// The window only moves forward: an event carrying a timestamp older than
// the open window spends that window's budget instead of reopening its own,
// because moving the window backward would mint a fresh budget inside one
// real second. The counters still race benignly at a window boundary — a
// straggler may lose its slot to the reset — but every residual race drops
// a line rather than printing an extra one.
type logSampler struct {
	limit   int64
	window  atomic.Int64
	count   atomic.Int64
	dropped atomic.Int64
}

// admit reports whether this event may log, and how many events were dropped
// since the last admitted one. now is a unix-second timestamp.
func (l *logSampler) admit(now int64) (bool, int64) {
	for {
		window := l.window.Load()
		if now <= window {
			if l.count.Add(1) <= l.limit {
				return true, l.dropped.Swap(0)
			}
			l.dropped.Add(1)
			return false, 0
		}
		if l.window.CompareAndSwap(window, now) {
			// The winner takes the first slot of the fresh window.
			l.count.Store(1)
			return true, l.dropped.Swap(0)
		}
	}
}
