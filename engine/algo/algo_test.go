package algo

import (
	"fmt"
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
		{"a single request a minute", "GCRA", Window{Requests: 1, Period: time.Minute, Burst: 1}},
		// 10101 a second is an exact interval of 99.0001 microseconds, which
		// rounds up to the floor of 100; the enforced 10000 a second is under
		// 1% stricter, so the period need not divide.
		{"a GCRA rate whose interval rounds up to the emission floor", "GCRA",
			Window{Requests: 10_101, Period: time.Second, Burst: 10_101}},
		{"a GCRA rate of exactly one request per microsecond", "GCRA",
			Window{Requests: 1_000_000, Period: time.Second, Burst: 1_000_000}},
		// One request a day is an emission interval of 86400000000 microseconds,
		// so a bucket of 11574 such requests stays under the depth bound of 10^15.
		{"a GCRA bucket at the deepest supported depth", "GCRA",
			Window{Requests: 1, Period: 24 * time.Hour, Burst: 11_574}},
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
		{"a GCRA rate just past one request per microsecond", "GCRA",
			Window{Requests: 1_000_001, Period: time.Second, Burst: 1_000_001}, "requests"},
		{"a GCRA rate near the resolution that does not divide the period", "GCRA",
			Window{Requests: 500_001, Period: time.Second, Burst: 500_001}, "period"},
		{"a GCRA bucket deeper than the supported maximum", "GCRA",
			Window{Requests: 1, Period: 24 * time.Hour, Burst: 20_000}, "burst"},
		{"a GCRA bucket one request past the deepest supported depth", "GCRA",
			Window{Requests: 1, Period: 24 * time.Hour, Burst: 11_575}, "burst"},
		// 10102 a second rounds up to an emission interval of 99 microseconds,
		// the longest one under the floor of 100, and does not divide a second.
		{"a GCRA rate just under the emission floor that does not divide the period", "GCRA",
			Window{Requests: 10_102, Period: time.Second, Burst: 10_102}, "period"},
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
			before := lookupOf(c.algo)
			defer func() {
				if recover() == nil {
					t.Errorf("Register(%+v) returned, want a panic", c.algo)
				}
				assertRegistryKept(t, c.algo, before)
			}()
			Register(c.algo)
		})
	}
}

// lookup is what the registry resolves for the name and the dispatch code of
// one declaration: the algorithm found for each, as its name and code, or an
// empty string for nothing.
type lookup struct{ byName, byID string }

// assertRegistryKept checks that a refused declaration left the registry as
// it was: what the declaration's name and code resolve to, and the names
// listed.
func assertRegistryKept(t *testing.T, a Algorithm, before lookup) {
	t.Helper()
	if after := lookupOf(a); after != before {
		t.Errorf("after the refused Register(%+v), the registry resolves %+v, want %+v as before", a, after, before)
	}
	if got, want := Names(), []string{"GCRA", "FixedWindow"}; !slices.Equal(got, want) {
		t.Errorf("after the refused Register(%+v), Names() = %q, want %q", a, got, want)
	}
}

func lookupOf(a Algorithm) lookup {
	var l lookup
	if found, ok := ByName(a.Name()); ok {
		l.byName = fmt.Sprintf("%s/%d", found.Name(), found.ID())
	}
	if found, ok := ByID(a.ID()); ok {
		l.byID = fmt.Sprintf("%s/%d", found.Name(), found.ID())
	}
	return l
}

// A name or a dispatch code that no algorithm registered resolves to nothing.
// The compiler refuses a rule whose algorithm name does not resolve.
func TestRegistryResolvesNothingForAnUnregisteredValue(t *testing.T) {
	t.Run("a name", func(t *testing.T) {
		if a, ok := ByName("SlidingLog"); ok {
			t.Errorf("ByName(%q) = %v, %t; want nothing", "SlidingLog", a, ok)
		}
	})
	t.Run("the zero dispatch code", func(t *testing.T) {
		if a, ok := ByID(0); ok {
			t.Errorf("ByID(0) = %v, %t; want nothing", a, ok)
		}
	})
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
