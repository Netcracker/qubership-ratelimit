package records

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	goredis "github.com/redis/go-redis/v9"
)

// The scripts below are why this store is one component rather than two.
//
// Every step a command takes has to be indivisible: acceptance binds the key,
// consumes the token, and claims the lease together, and each batch verifies
// the fencing token, deletes, and advances the progress together. Read-then-
// write from the client would leave a gap in each of them, and each gap is a
// way to delete twice or to lose what was deleted. The record, the lease, the
// token, and the counters all carry the domain's hash tag, so they share one
// slot and one script may touch them all, on a cluster as well.

// acceptScript is the point of no return, as one write.
//
// It reads the record first, so a retry of a finished execution answers what it
// did rather than a refusal for the token it consumed itself. The lease is
// checked before the token is consumed: a command refused because another sweep
// is running must not spend the look that authorized it.
//
// KEYS: record, lease, token (token may be empty).
// ARGV: command, fencing, retention ms, lease ms.
var acceptScript = goredis.NewScript(`
local existing = redis.call('HGET', KEYS[1], 'command')
if existing then
  return {'existing'}
end

local held = redis.call('GET', KEYS[2])
if held then
  local ttl = redis.call('PTTL', KEYS[2])
  return {'busy', tostring(ttl)}
end

local token = false
if KEYS[3] and KEYS[3] ~= '' then
  token = redis.call('GET', KEYS[3])
  if not token then
    return {'no_token'}
  end
  redis.call('DEL', KEYS[3])
end

redis.call('HSET', KEYS[1], 'command', ARGV[1], 'fencing', ARGV[2])
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('SET', KEYS[2], ARGV[2], 'PX', ARGV[4])
if token then
  return {'accepted', token}
end
return {'accepted'}
`)

// batchScript is one step of a sweep: prove the domain is still ours, delete,
// and record what that made true.
//
// The deletions use UNLINK so a large batch is reclaimed off the main thread.
// Progress is written whole rather than incremented, because the fencing token
// makes this the only writer.
//
// KEYS: record, lease, then the counter keys to delete.
// ARGV: fencing, progress JSON.
var batchScript = goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then
  return 'lost'
end
for i = 3, #KEYS do
  redis.call('UNLINK', KEYS[i])
end
redis.call('HSET', KEYS[1], 'progress', ARGV[2])
return 'ok'
`)

// commitScript writes the terminal outcome and releases the lease, only under
// the writer's own live token: a walker that lost the domain does not get to say
// how the command ended.
//
// KEYS: record, lease. ARGV: fencing, outcome JSON, retention ms.
var commitScript = goredis.NewScript(`
if redis.call('GET', KEYS[2]) ~= ARGV[1] then
  return 'lost'
end
redis.call('HSET', KEYS[1], 'outcome', ARGV[2], 'terminal', '1')
redis.call('PEXPIRE', KEYS[1], ARGV[3])
redis.call('DEL', KEYS[2])
return 'ok'
`)

// finalizeScript records the outcome of a sweep whose walker died, as a
// compare-and-set against the still-empty outcome. A live lease means somebody
// is still working, and then nothing is written.
//
// KEYS: record, lease. ARGV: outcome JSON, retention ms.
var finalizeScript = goredis.NewScript(`
if redis.call('EXISTS', KEYS[1]) == 0 then
  return 'gone'
end
if redis.call('HGET', KEYS[1], 'terminal') then
  return 'already'
end
if redis.call('GET', KEYS[2]) then
  return 'alive'
end
redis.call('HSET', KEYS[1], 'outcome', ARGV[1], 'terminal', '1')
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return 'ok'
`)

// resetScript is the whole addressed reset: bind the key, drop the computed
// keys, record the count. The form has no intermediate states because it has no
// intermediate steps.
//
// KEYS: record, then the computed counter keys.
// ARGV: command, retention ms, dryRun flag.
var resetScript = goredis.NewScript(`
local existing = redis.call('HGET', KEYS[1], 'command')
if existing then
  return {'replayed', existing, redis.call('HGET', KEYS[1], 'count')}
end

local count = 0
for i = 2, #KEYS do
  if ARGV[3] == '1' then
    count = count + redis.call('EXISTS', KEYS[i])
  else
    count = count + redis.call('UNLINK', KEYS[i])
  end
end

redis.call('HSET', KEYS[1], 'command', ARGV[1], 'terminal', '1', 'count', tostring(count))
redis.call('PEXPIRE', KEYS[1], ARGV[2])
return {'done', ARGV[1], tostring(count)}
`)

// Redis keeps records in the shared counter store.
type Redis struct {
	rdb goredis.UniversalClient
}

var _ Store = (*Redis)(nil)

// NewRedis wraps a ready client. Its lifecycle belongs to the caller.
func NewRedis(rdb goredis.UniversalClient) *Redis {
	return &Redis{rdb: rdb}
}

// Lookup reads a binding and the domain lease in one round trip.
func (r *Redis) Lookup(ctx context.Context, keys Keys) (Record, error) {
	pipe := r.rdb.Pipeline()
	fields := pipe.HGetAll(ctx, keys.Record)
	holder := pipe.Get(ctx, keys.Lease)
	ttl := pipe.PTTL(ctx, keys.Lease)
	if _, err := pipe.Exec(ctx); err != nil && !errors.Is(err, goredis.Nil) {
		return Record{}, fmt.Errorf("records: lookup %s: %w", keys.Record, err)
	}

	record, err := recordOf(fields.Val())
	if err != nil {
		return Record{}, fmt.Errorf("records: read %s: %w", keys.Record, err)
	}
	if !record.Found {
		return record, nil
	}
	if held, err := holder.Result(); err == nil {
		record.LeaseHolder = held
		record.LeaseTTL = ttl.Val()
	}
	return record, nil
}

// Accept performs the atomic acceptance of a bulk command.
func (r *Redis) Accept(ctx context.Context, acceptance Acceptance) (Accepted, error) {
	res, err := acceptScript.Run(ctx, r.rdb,
		[]string{acceptance.Keys.Record, acceptance.Keys.Lease, acceptance.Keys.Token},
		acceptance.Command, acceptance.Fencing,
		Retention.Milliseconds(), acceptance.LeaseTTL.Milliseconds()).Result()
	if err != nil {
		return Accepted{}, fmt.Errorf("records: accept %s: %w", acceptance.Keys.Record, err)
	}

	reply, verdict, err := verdictOf(res, "accept")
	if err != nil {
		return Accepted{}, err
	}
	switch verdict {
	case "existing":
		existing, err := r.Lookup(ctx, acceptance.Keys)
		if err != nil {
			return Accepted{}, err
		}
		return Accepted{Existing: existing}, nil
	case "busy":
		ttl, _ := reply[1].(string)
		return Accepted{SweepBusy: true, LeaseTTL: millis(ttl)}, nil
	case "no_token":
		return Accepted{TokenMissing: true}, nil
	case "accepted":
		out := Accepted{OK: true}
		if len(reply) > 1 {
			token, _ := reply[1].(string)
			out.Token = []byte(token)
		}
		return out, nil
	default:
		return Accepted{}, fmt.Errorf("records: accept answered an unknown verdict %q", verdict)
	}
}

// Batch verifies the fencing token, deletes, and advances the progress.
func (r *Redis) Batch(ctx context.Context, batch Batch) error {
	progress, err := json.Marshal(batch.Progress)
	if err != nil {
		return fmt.Errorf("records: encode the progress: %w", err)
	}

	keys := append([]string{batch.Keys.Record, batch.Keys.Lease}, batch.Delete...)
	res, err := batchScript.Run(ctx, r.rdb, keys, batch.Fencing, string(progress)).Result()
	if err != nil {
		return fmt.Errorf("records: batch %s: %w", batch.Keys.Record, err)
	}
	if res == "lost" {
		return ErrLeaseLost
	}
	return nil
}

// Commit records the terminal outcome and releases the lease.
func (r *Redis) Commit(ctx context.Context, commit Commit) error {
	outcome, err := json.Marshal(commit.Outcome)
	if err != nil {
		return fmt.Errorf("records: encode the outcome: %w", err)
	}

	res, err := commitScript.Run(ctx, r.rdb,
		[]string{commit.Keys.Record, commit.Keys.Lease},
		commit.Fencing, string(outcome), Retention.Milliseconds()).Result()
	if err != nil {
		return fmt.Errorf("records: commit %s: %w", commit.Keys.Record, err)
	}
	if res == "lost" {
		return ErrLeaseLost
	}
	return nil
}

// Finalize records the outcome of a dead sweep, if none is recorded yet.
func (r *Redis) Finalize(ctx context.Context, finalize Finalize) (Record, error) {
	current, err := r.Lookup(ctx, finalize.Keys)
	if err != nil {
		return Record{}, err
	}
	if !current.Found || current.Terminal {
		return current, nil
	}

	// The progress the batches committed is what the failure discloses.
	outcome := finalize.Outcome
	outcome.Progress = current.Progress
	encoded, err := json.Marshal(outcome)
	if err != nil {
		return Record{}, fmt.Errorf("records: encode the outcome: %w", err)
	}

	if _, err := finalizeScript.Run(ctx, r.rdb,
		[]string{finalize.Keys.Record, finalize.Keys.Lease},
		string(encoded), Retention.Milliseconds()).Result(); err != nil {
		return Record{}, fmt.Errorf("records: finalize %s: %w", finalize.Keys.Record, err)
	}
	// Whoever won the compare-and-set, the record now says what happened.
	return r.Lookup(ctx, finalize.Keys)
}

// Reset runs the addressed reset as one atomic step.
func (r *Redis) Reset(ctx context.Context, addressed Addressed) (AddressedOutcome, error) {
	dryRun := "0"
	if addressed.DryRun {
		dryRun = "1"
	}

	keys := append([]string{addressed.Record}, addressed.Delete...)
	res, err := resetScript.Run(ctx, r.rdb, keys,
		addressed.Command, Retention.Milliseconds(), dryRun).Result()
	if err != nil {
		return AddressedOutcome{}, fmt.Errorf("records: reset %s: %w", addressed.Record, err)
	}

	reply, verdict, err := verdictOf(res, "reset")
	if err != nil {
		return AddressedOutcome{}, err
	}
	if len(reply) < 3 {
		return AddressedOutcome{}, fmt.Errorf("records: reset answered %d values, not 3", len(reply))
	}
	command, _ := reply[1].(string)
	count, _ := reply[2].(string)

	parsed, err := strconv.Atoi(count)
	if err != nil {
		return AddressedOutcome{}, fmt.Errorf("records: reset answered a count that is not a number: %q", count)
	}
	return AddressedOutcome{Replayed: verdict == "replayed", Command: command, Count: parsed}, nil
}

// Put stores a confirmation token under a TTL.
func (r *Redis) Put(ctx context.Context, key string, value []byte, ttl time.Duration) error {
	if err := r.rdb.Set(ctx, key, value, ttl).Err(); err != nil {
		return fmt.Errorf("records: put %s: %w", key, err)
	}
	return nil
}

// Get reads a confirmation token.
func (r *Redis) Get(ctx context.Context, key string) ([]byte, bool, error) {
	raw, err := r.rdb.Get(ctx, key).Bytes()
	if errors.Is(err, goredis.Nil) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("records: get %s: %w", key, err)
	}
	return raw, true, nil
}

// recordOf reads the stored hash.
func recordOf(fields map[string]string) (Record, error) {
	if len(fields) == 0 {
		return Record{}, nil
	}

	record := Record{
		Found:    true,
		Command:  fields["command"],
		Fencing:  fields["fencing"],
		Terminal: fields["terminal"] == "1",
	}
	if raw := fields["progress"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &record.Progress); err != nil {
			return Record{}, err
		}
	}
	if raw := fields["outcome"]; raw != "" {
		if err := json.Unmarshal([]byte(raw), &record.Outcome); err != nil {
			return Record{}, err
		}
		record.Progress = record.Outcome.Progress
	}
	// The addressed form records its count instead of an outcome document: its
	// whole result is that number.
	if raw := fields["count"]; raw != "" {
		count, err := strconv.Atoi(raw)
		if err != nil {
			return Record{}, err
		}
		record.Progress.Reset = count
	}
	return record, nil
}

// verdictOf unwraps the array reply the scripts answer with.
func verdictOf(res any, script string) ([]any, string, error) {
	reply, ok := res.([]any)
	if !ok || len(reply) == 0 {
		return nil, "", fmt.Errorf("records: %s answered %T, not a verdict", script, res)
	}
	verdict, _ := reply[0].(string)
	return reply, verdict, nil
}

// millis reads a PTTL reply, which is negative when the key has no expiry or is
// already gone.
func millis(raw string) time.Duration {
	value, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || value < 0 {
		return 0
	}
	return time.Duration(value) * time.Millisecond
}
