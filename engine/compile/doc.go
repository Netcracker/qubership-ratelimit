// Package compile turns the rules of one domain into an immutable snapshot.
//
// Compilation is a pure function of the object set: apply order, recreation, and
// timestamps do not reach the result, so every replica compiling the same rules
// produces the same snapshot. Order matters in exactly one place — the rule list
// of a first-match block, which is the order of lines in one file.
//
// A policy compiles whole or not at all. A reference that does not resolve — an
// unknown key, an unknown group, an operator that the key's type rejects — makes
// the entire policy invalid and keeps every one of its rules out of the
// snapshot. Enforcing the surviving rules would be worse than enforcing none: a
// cascade whose first rule went missing hands its traffic to the next one, which
// silently applies the wrong limit to the wrong clients.
package compile
