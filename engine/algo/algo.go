// Package algo describes the counting algorithms to the Go side of the engine.
//
// The counting math itself is not here. A decision must read counter state,
// judge it, and write it back as one indivisible step, which only the store can
// offer; splitting those across a round trip lets two replicas admit the same
// last request. What Go needs instead is a passport for each algorithm: the code
// the store dispatches on, the name that reaches both the custom resource and
// the counter key, and the window fields the algorithm accepts.
package algo

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"time"
)

// ID is the dispatch code handed to the store; the counter key carries the
// algorithm name, never this number. The store dispatches its server-side math
// on the code, and counter state outlives a deploy within its TTL — so a
// retired code is never reused: a new algorithm behind an old code would
// reinterpret foreign persisted state.
type ID uint8

const (
	GCRAID        ID = 1
	FixedWindowID ID = 2
)

// MaxPeriod is the longest window the engine counts over. Beyond a day a limit
// stops behaving like a rate and starts behaving like an accounting record,
// which counters are the wrong tool for.
const MaxPeriod = 24 * time.Hour

// Window is one entry of a rule's rate list: an independent bucket with its own
// algorithm. Requests and Period are mandatory for every algorithm; the rest
// are optional, and Check rejects an optional field the algorithm does not
// declare. A set field is a non-zero field, so a future field whose zero value
// is meaningful must be a pointer.
type Window struct {
	Requests int64
	Period   time.Duration
	Burst    int64
}

// mandatory are the fields every algorithm consumes by definition.
var mandatory = map[string]bool{"Requests": true, "Period": true}

// PeriodMicros returns the window period in whole microseconds — the unit all
// counter math runs in. checkCommon guarantees whole seconds, so nothing is
// truncated here.
func PeriodMicros(w Window) int64 {
	return int64(w.Period / time.Microsecond)
}

// Algorithm is what Go knows about a counting algorithm. Its methods are
// unexported on purpose: algorithms are added by editing this package, never
// from outside, and Check stays the only door into validation.
//
// An algorithm's persisted state must not encode Requests or Burst: those
// parameters tune without re-bucketing, so the state has to stay
// interpretable when they change. Each algorithm defines what tuning
// preserves — fixed window keeps the consumed count, GCRA keeps drain depth
// in time, so its consumed requests rescale with the rate.
type Algorithm interface {
	// ID is the value the store dispatches on.
	ID() ID

	// Name is the enum value authors write in a rule and the segment the counter
	// key carries, so switching a live rule's algorithm starts fresh buckets.
	Name() string

	// consumes lists the optional Window fields this algorithm gives meaning
	// to, by struct field name. Register panics on a name Window does not
	// carry, so a typo dies at init rather than in production validation.
	consumes() []string

	// validate checks the semantics of the consumed fields. Foreign-field
	// rejection and the shared bounds are Check's job.
	validate(Window) error
}

// Check reports whether the window is expressible in this algorithm. A set
// field the algorithm does not consume is an error, so an author can never
// write a parameter that is silently ignored — a new Window field gets that
// rejection automatically. Check takes resolved windows — defaults, burst
// included, are the compiler's job — and the engine runs it itself rather
// than trusting the resource schema: a library cannot assume its caller
// validated anything.
func Check(a Algorithm, w Window) error {
	consumed := make(map[string]bool, len(a.consumes()))
	for _, f := range a.consumes() {
		consumed[f] = true
	}
	v := reflect.ValueOf(w)
	for i := range v.NumField() {
		name := v.Type().Field(i).Name
		if mandatory[name] || consumed[name] || v.Field(i).IsZero() {
			continue
		}
		return fmt.Errorf("%s does not accept %s", a.Name(), strings.ToLower(name))
	}
	if err := checkCommon(w); err != nil {
		return err
	}
	return a.validate(w)
}

var (
	byName = map[string]Algorithm{}
	byID   = map[ID]Algorithm{}
)

// Register adds an algorithm to the registry. Algorithms register from their own
// init, so linking one in is what makes it available, and a broken declaration
// kills the process at start instead of surfacing on live validation.
func Register(a Algorithm) {
	if _, taken := byName[a.Name()]; taken {
		panic(fmt.Sprintf("algo: name %q registered twice", a.Name()))
	}
	if _, taken := byID[a.ID()]; taken {
		panic(fmt.Sprintf("algo: id %d registered twice", a.ID()))
	}
	typ := reflect.TypeFor[Window]()
	for _, f := range a.consumes() {
		if _, ok := typ.FieldByName(f); !ok {
			panic(fmt.Sprintf("algo: %s consumes unknown Window field %q", a.Name(), f))
		}
		if mandatory[f] {
			panic(fmt.Sprintf("algo: %s declares mandatory field %q", a.Name(), f))
		}
	}
	byName[a.Name()] = a
	byID[a.ID()] = a
}

// ByName resolves the enum value written in a rule.
func ByName(name string) (Algorithm, bool) {
	a, ok := byName[name]
	return a, ok
}

// ByID resolves a dispatch code.
func ByID(id ID) (Algorithm, bool) {
	a, ok := byID[id]
	return a, ok
}

// Names lists every registered algorithm, sorted by dispatch code, for error
// messages that tell the author what they could have written instead.
func Names() []string {
	ids := make([]ID, 0, len(byID))
	for id := range byID {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]string, len(ids))
	for i, id := range ids {
		out[i] = byID[id].Name()
	}
	return out
}

// checkCommon holds the bounds every algorithm shares. Whole seconds are a
// hard requirement, not a style choice: the counter key carries the window as
// integer seconds, so two sub-second periods would truncate into one key and
// two different limits would grind the same state.
func checkCommon(w Window) error {
	if w.Requests < 1 {
		return fmt.Errorf("requests must be at least 1, got %d", w.Requests)
	}
	if w.Period < time.Second || w.Period > MaxPeriod || w.Period%time.Second != 0 {
		return fmt.Errorf("period must be whole seconds within [1s, %s], got %s", MaxPeriod, w.Period)
	}
	return nil
}
