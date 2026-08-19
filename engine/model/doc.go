// Package model is the rule set as the engine sees it: blocks with their routes
// and modes, rules with their predicates, counting axes and windows, and the
// named client groups they draw on.
//
// These are plain structures with no schema annotations and no knowledge of
// where the rules came from. The operator converts custom resources into them;
// a service embedding the engine builds them directly. Keeping the conversion
// outside is what lets the resource schema change without touching matching.
//
// Values are stored as authored: the defaults — burst, algorithm, mode,
// behavior — stay empty here and resolve during compilation, so the snapshot,
// not the model, carries the resolved truth.
package model
