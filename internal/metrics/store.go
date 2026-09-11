package metrics

import (
	"context"
	"errors"
	"net"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"github.com/netcracker/qubership-ratelimit/engine/store"
)

// InstrumentStore wraps a counter store with the roundtrip histogram and the
// error counter of one domain. The wrapper carries the domain label so no key
// parsing happens on the hot path; only Decide is observed — Peek and Reset
// belong to the management API, not to the traffic the histograms describe.
func InstrumentStore(domain string, next store.Store) store.Store {
	return instrumentedStore{domain: domain, next: next}
}

type instrumentedStore struct {
	domain string
	next   store.Store
}

func (s instrumentedStore) Decide(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	start := time.Now()
	verdicts, err := s.next.Decide(ctx, buckets, cost)
	StoreRoundtrip.WithLabelValues(s.domain).Observe(time.Since(start).Seconds())
	if err != nil {
		StoreErrors.WithLabelValues(s.domain, storeErrorReason(err)).Inc()
	}
	return verdicts, err
}

func (s instrumentedStore) Peek(ctx context.Context, buckets []store.Bucket, cost int64) ([]store.Verdict, error) {
	return s.next.Peek(ctx, buckets, cost)
}

func (s instrumentedStore) Reset(ctx context.Context, keys []string) error {
	return s.next.Reset(ctx, keys)
}

// storeErrorReason folds a store error into the fixed reason set. Timeout is
// load or distance; server means the store answered an error — a script or
// command problem, which no retry cures; other is connectivity.
func storeErrorReason(err error) string {
	var netErr net.Error
	switch {
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		return "timeout"
	case errors.As(err, &netErr) && netErr.Timeout():
		return "timeout"
	default:
	}
	var redisErr goredis.Error
	if errors.As(err, &redisErr) {
		return "server"
	}
	return "other"
}
