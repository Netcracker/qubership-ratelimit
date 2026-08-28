package algo

import "fmt"

func init() { Register(gcra{}) }

// maxTauMicros bounds the bucket depth burst×(period/requests) to ~31 years in
// microseconds, so depth arithmetic and duration conversions stay far from
// int64 overflow.
const maxTauMicros = int64(1_000_000_000_000_000)

// gcra smooths a stream: it spaces requests evenly over the period and lets
// burst govern how much of that spacing a caller may claim at once. It has no
// window boundary, so it never doubles traffic across one.
type gcra struct{}

func (gcra) ID() ID       { return GCRAID }
func (gcra) Name() string { return "GCRA" }

func (gcra) consumes() []string { return []string{"Burst"} }

// exactEmissionFloor is the emission interval, in microseconds, above which
// rounding to a whole microsecond keeps the enforced rate within 1% of the
// configured one. Below it the rounding is no longer a rounding — 500001/s
// would enforce as 500000/s — so the period must divide evenly instead.
const exactEmissionFloor = 100

// EmissionMicros returns the GCRA emission interval in whole microseconds,
// rounded up so the enforced rate errs strict, never loose. This is the one
// formula every store implementation and the server-side script derive the
// interval from; validation keeps the rounding under 1% by requiring exact
// divisibility near the resolution.
func EmissionMicros(w Window) int64 {
	return (PeriodMicros(w) + w.Requests - 1) / w.Requests
}

// TauMicros returns the GCRA bucket depth in whole microseconds — the same
// single-source rule as EmissionMicros. Validation bounds it, so depth
// arithmetic and duration conversions stay far from int64 overflow.
func TauMicros(w Window) int64 {
	return EmissionMicros(w) * w.Burst
}

func (gcra) validate(w Window) error {
	if w.Burst < 1 {
		return fmt.Errorf("burst must be at least 1 in a resolved window, got %d", w.Burst)
	}
	periodMicros := PeriodMicros(w)
	if w.Requests > periodMicros {
		return fmt.Errorf("requests exceed GCRA resolution of one per microsecond: %d per %s",
			w.Requests, w.Period)
	}
	emission := EmissionMicros(w)
	if emission < exactEmissionFloor && periodMicros%w.Requests != 0 {
		return fmt.Errorf(
			"a rate this high must divide the period evenly at microsecond resolution: %d per %s does not",
			w.Requests, w.Period)
	}
	if w.Burst > maxTauMicros/emission {
		return fmt.Errorf("bucket depth burst×(period/requests) exceeds the supported maximum, burst %d is too large",
			w.Burst)
	}
	return nil
}
