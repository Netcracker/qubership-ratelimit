package algo

import (
	"testing"
	"time"
)

func TestRegistryResolvesBothAlgorithms(t *testing.T) {
	for name, id := range map[string]ID{"GCRA": GCRAID, "FixedWindow": FixedWindowID} {
		a, ok := ByName(name)
		if !ok {
			t.Fatalf("ByName(%q): not registered", name)
		}
		if a.ID() != id {
			t.Errorf("ByName(%q).ID() = %d, want %d", name, a.ID(), id)
		}
		if b, ok := ByID(id); !ok || b.Name() != name {
			t.Errorf("ByID(%d) did not resolve back to %q", id, name)
		}
	}
}

func TestCheck(t *testing.T) {
	minute := time.Minute

	cases := []struct {
		name    string
		algo    string
		window  Window
		wantErr bool
	}{
		{"gcra plain", "GCRA", Window{Requests: 100, Period: minute, Burst: 100}, false},
		{"gcra with burst", "GCRA", Window{Requests: 100, Period: minute, Burst: 20}, false},
		{"burst not resolved", "GCRA", Window{Requests: 100, Period: minute}, true},
		{"fixed window plain", "FixedWindow", Window{Requests: 10000, Period: 24 * time.Hour}, false},
		{"foreign field rejected", "FixedWindow", Window{Requests: 100, Period: minute, Burst: 20}, true},
		{"requests below one", "GCRA", Window{Requests: 0, Period: minute}, true},
		{"period beyond a day", "GCRA", Window{Requests: 100, Period: 48 * time.Hour}, true},
		{"period not set", "GCRA", Window{Requests: 100}, true},
		{"sub-second period", "GCRA", Window{Requests: 100, Period: 500 * time.Millisecond}, true},
		{"fractional seconds", "GCRA", Window{Requests: 100, Period: 90*time.Second + 500*time.Millisecond}, true},
		{"beyond gcra resolution", "GCRA",
			Window{Requests: 61_000_000, Period: minute, Burst: 61_000_000}, true},
		{"bucket depth overflow", "GCRA",
			Window{Requests: 1, Period: 24 * time.Hour, Burst: 20_000}, true},
		{"inexact near-resolution rate", "GCRA",
			Window{Requests: 500_001, Period: time.Second, Burst: 500_001}, true},
		{"exact near-resolution rate", "GCRA",
			Window{Requests: 500_000, Period: time.Second, Burst: 500_000}, false},
		{"negative burst", "GCRA", Window{Requests: 100, Period: minute, Burst: -1}, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := ByName(c.algo)
			if !ok {
				t.Fatalf("%s is not registered", c.algo)
			}
			err := Check(a, c.window)
			if (err != nil) != c.wantErr {
				t.Errorf("Check(%s, %+v) error = %v, want error: %v", c.algo, c.window, err, c.wantErr)
			}
		})
	}
}

// TestRegisterRejectsBrokenDeclarations pins the fail-fast contract: a passport
// declaring a field Window does not carry, or a mandatory one, must not make it
// into the registry.
func TestRegisterRejectsBrokenDeclarations(t *testing.T) {
	cases := []struct {
		name string
		algo Algorithm
	}{
		{"unknown field", declaring{id: 200, name: "BadField", fields: []string{"Precision"}}},
		{"mandatory field", declaring{id: 201, name: "BadMandatory", fields: []string{"Period"}}},
		{"name taken", declaring{id: 202, name: "GCRA"}},
		{"id taken", declaring{id: GCRAID, name: "UniqueEnough"}},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("Register accepted a broken declaration")
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
	got := Names()
	want := []string{"GCRA", "FixedWindow"}

	if len(got) != len(want) {
		t.Fatalf("Names() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Names() = %v, want %v", got, want)
		}
	}
}
