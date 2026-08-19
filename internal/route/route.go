// Package route matches request paths against the route of a limit block.
//
// A matcher is compiled once, when the domain is compiled, and is read-only
// afterwards: every replica evaluates the same snapshot concurrently.
package route

import (
	"fmt"
	"strings"
)

// Kind is how a matcher compares a path.
type Kind uint8

const (
	// Exact compares the whole path.
	Exact Kind = iota

	// Prefix compares the leading bytes of the path.
	Prefix

	// Template compares segment by segment and captures the placeholders.
	Template
)

// Matcher matches request paths.
type Matcher struct {
	kind  Kind
	value string

	// segments and names are set for Template only. A segment is either a
	// literal or a placeholder; names lists the placeholder names in the order
	// they appear.
	segments []segment
	names    []string
}

type segment struct {
	literal string
	name    string // non-empty for a placeholder
}

// Compile turns one path match into a matcher.
//
// The CRD rejects a malformed template before it reaches here, so an error means
// either a client that bypassed validation or the one check the cost estimator
// would not accept in CEL: placeholder names have to be unique, because two
// placeholders of one name would capture into one descriptor key.
func Compile(kind Kind, value string) (*Matcher, error) {
	if value == "" {
		return nil, fmt.Errorf("path value is empty")
	}
	if kind != Template {
		return &Matcher{kind: kind, value: value}, nil
	}

	parts := strings.Split(value, "/")
	segments := make([]segment, 0, len(parts))
	var names []string
	seen := make(map[string]struct{}, len(parts))
	for _, part := range parts {
		if !strings.HasPrefix(part, "{") || !strings.HasSuffix(part, "}") || len(part) < 3 {
			segments = append(segments, segment{literal: part})
			continue
		}
		name := part[1 : len(part)-1]
		if _, dup := seen[name]; dup {
			return nil, fmt.Errorf("template %q repeats placeholder %q", value, name)
		}
		seen[name] = struct{}{}
		names = append(names, name)
		segments = append(segments, segment{name: name})
	}
	return &Matcher{kind: Template, value: value, segments: segments, names: names}, nil
}

// Names returns the placeholder names of a template matcher, in order. The
// result must be treated as read-only.
func (m *Matcher) Names() []string { return m.names }

// Match reports whether the path matches, and returns the captured segments of a
// template. Captures are nil for the other kinds and for a template without
// placeholders.
func (m *Matcher) Match(path string) (map[string]string, bool) {
	switch m.kind {
	case Exact:
		return nil, path == m.value
	case Prefix:
		return nil, strings.HasPrefix(path, m.value)
	}

	parts := strings.Split(path, "/")
	if len(parts) != len(m.segments) {
		return nil, false
	}

	var captures map[string]string
	for i, seg := range m.segments {
		if seg.name == "" {
			if parts[i] != seg.literal {
				return nil, false
			}
			continue
		}
		// A placeholder matches exactly one non-empty segment, so an empty one
		// fails the match instead of capturing an empty value.
		if parts[i] == "" {
			return nil, false
		}
		if captures == nil {
			captures = make(map[string]string, len(m.names))
		}
		captures[seg.name] = parts[i]
	}
	return captures, true
}

// PathAxis is the value the path counter axis takes for a request this matcher
// accepted.
//
// A template yields the template itself rather than the request path, which caps
// the cardinality of the axis by construction: one bucket per route, not one per
// order id. A prefix yields the raw path, so an axis of path under a prefix route
// is as wide as the traffic.
func (m *Matcher) PathAxis(path string) string {
	if m.kind == Template {
		return m.value
	}
	return path
}
