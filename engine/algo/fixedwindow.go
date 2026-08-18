package algo

func init() { Register(fixedWindow{}) }

// fixedWindow counts a budget that resets on a calendar boundary, which is what
// a daily quota means to the person who wrote it. Windows are aligned to Unix
// epoch boundaries — a day resets at midnight UTC, an hour on the hour — never
// at the first request.
type fixedWindow struct{}

func (fixedWindow) ID() ID       { return FixedWindowID }
func (fixedWindow) Name() string { return "FixedWindow" }

// consumes is empty: burst has no meaning here — the whole budget is already
// claimable at once — and Check rejects it along with any other foreign field.
func (fixedWindow) consumes() []string { return nil }

func (fixedWindow) validate(Window) error { return nil }
