package algo

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// algorithm resolves a registered algorithm by the name a rule carries.
func algorithm(t *testing.T, name string) Algorithm {
	t.Helper()
	a, ok := ByName(name)
	if !ok {
		t.Fatalf("ByName(%q) found nothing; registered: %q", name, Names())
	}
	return a
}

func TestRegistryBindsEachNameToItsDispatchCode(t *testing.T) {
	for _, c := range []struct {
		name string
		id   ID
	}{
		{"GCRA", GCRAID},
		{"FixedWindow", FixedWindowID},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := algorithm(t, c.name).ID(); got != c.id {
				t.Errorf("ByName(%q).ID() = %d, want %d", c.name, got, c.id)
			}
			byID, ok := ByID(c.id)
			if !ok {
				t.Fatalf("ByID(%d) found nothing, want %s", c.id, c.name)
			}
			if got := byID.Name(); got != c.name {
				t.Errorf("ByID(%d).Name() = %q, want %q", c.id, got, c.name)
			}
		})
	}
}

func TestCheckAcceptsAnExpressibleWindow(t *testing.T) {
	for _, c := range []struct {
		name   string
		algo   string
		window Window
	}{
		{"a GCRA window with a full bucket", "GCRA", Window{Requests: 100, Period: time.Minute, Burst: 100}},
		{"a GCRA window with a smaller burst", "GCRA", Window{Requests: 100, Period: time.Minute, Burst: 20}},
		{"a fixed window of exactly a day", "FixedWindow", Window{Requests: 10000, Period: 24 * time.Hour}},
		{"a GCRA rate that divides the period at microsecond resolution", "GCRA",
			Window{Requests: 500_000, Period: time.Second, Burst: 500_000}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if err := Check(algorithm(t, c.algo), c.window); err != nil {
				t.Errorf("Check(%s, %+v) = %q, want nil", c.algo, c.window, err)
			}
		})
	}
}

// Each window breaks the bound its row names and is otherwise valid, burst
// included, except that a GCRA rate past one request per microsecond cannot
// avoid breaking the division rule as well. Each row therefore also requires
// the refusal to name the window field the author has to change, the field the
// InvalidWindow message points the author at; that check keeps a refusal by
// another bound from passing for the bound under test.
func TestCheckRejectsAnInexpressibleWindow(t *testing.T) {
	for _, c := range []struct {
		name   string
		algo   string
		window Window
		field  string
	}{
		{"a GCRA window whose burst is not resolved", "GCRA",
			Window{Requests: 100, Period: time.Minute}, "burst"},
		{"a negative burst", "GCRA", Window{Requests: 100, Period: time.Minute, Burst: -1}, "burst"},
		{"a burst on a fixed window", "FixedWindow", Window{Requests: 100, Period: time.Minute, Burst: 20}, "burst"},
		{"requests below one", "GCRA", Window{Requests: 0, Period: time.Minute, Burst: 100}, "requests"},
		{"a period of two days", "GCRA", Window{Requests: 100, Period: 48 * time.Hour, Burst: 100}, "period"},
		{"a fixed window one second longer than a day", "FixedWindow",
			Window{Requests: 10000, Period: 24*time.Hour + time.Second}, "period"},
		{"no period", "FixedWindow", Window{Requests: 100}, "period"},
		{"a sub-second period", "GCRA", Window{Requests: 100, Period: 500 * time.Millisecond, Burst: 100}, "period"},
		{"a period of fractional seconds", "GCRA",
			Window{Requests: 100, Period: 90*time.Second + 500*time.Millisecond, Burst: 100}, "period"},
		{"a GCRA rate past one request per microsecond", "GCRA",
			Window{Requests: 61_000_000, Period: time.Minute, Burst: 61_000_000}, "requests"},
		{"a GCRA rate near the resolution that does not divide the period", "GCRA",
			Window{Requests: 500_001, Period: time.Second, Burst: 500_001}, "period"},
		{"a GCRA bucket deeper than the supported maximum", "GCRA",
			Window{Requests: 1, Period: 24 * time.Hour, Burst: 20_000}, "burst"},
	} {
		t.Run(c.name, func(t *testing.T) {
			err := Check(algorithm(t, c.algo), c.window)
			if err == nil {
				t.Fatalf("Check(%s, %+v) = nil, want an error naming %s", c.algo, c.window, c.field)
			}
			if !strings.Contains(err.Error(), c.field) {
				t.Errorf("Check(%s, %+v) = %q, want an error naming %s", c.algo, c.window, err, c.field)
			}
		})
	}
}

func TestRegisterPanicsOnABrokenDeclaration(t *testing.T) {
	for _, c := range []struct {
		name string
		algo Algorithm
	}{
		{"a field Window does not carry", declaring{id: 200, name: "BadField", fields: []string{"Precision"}}},
		{"a mandatory field", declaring{id: 201, name: "BadMandatory", fields: []string{"Period"}}},
		{"a name already registered", declaring{id: 202, name: "GCRA"}},
		{"a dispatch code already registered", declaring{id: GCRAID, name: "UniqueEnough"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) returned, want a panic", c.algo)
				}
			}()
			Register(c.algo)
		})
	}
}

// declaring is a minimal passport for declaration tests. It never reaches the
// registry: Register panics before storing it.
type declaring struct {
	id     ID
	name   string
	fields []string
}

func (d declaring) ID() ID                { return d.id }
func (d declaring) Name() string          { return d.name }
func (d declaring) consumes() []string    { return d.fields }
func (d declaring) validate(Window) error { return nil }

func TestNamesAreOrderedByDispatchCode(t *testing.T) {
	if got, want := Names(), []string{"GCRA", "FixedWindow"}; !slices.Equal(got, want) {
		t.Errorf("Names() = %q, want %q", got, want)
	}
}
