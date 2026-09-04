package compile

import (
	"sort"
	"strings"

	"github.com/netcracker/qubership-ratelimit/engine/model"
)

// compileRoutes validates a block's routes and collects its template
// captures: block-scoped descriptor keys, sorted. A capture that shadows a
// mapped key is the one informational finding of the compiler — inside the
// block the capture wins, and the author should know.
func (c *blockCompiler) compileRoutes(b model.Block) ([]Route, []string) {
	// No routes is the documented "whole domain" form: the block matches
	// every request, with no captures and the raw path as the axis.
	routes := make([]Route, 0, len(b.Target.Routes))
	captures := map[string]struct{}{}
	for _, r := range b.Target.Routes {
		routes = append(routes, c.compileRoute(b, r, captures))
	}

	sorted := make([]string, 0, len(captures))
	for name := range captures {
		sorted = append(sorted, name)
	}
	sort.Strings(sorted)
	return routes, sorted
}

func (c *blockCompiler) compileRoute(b model.Block, r model.Route, captures map[string]struct{}) Route {
	out := Route{Type: r.Path.Type, Value: r.Path.Value}

	if !strings.HasPrefix(r.Path.Value, "/") {
		c.fail(b.Name, "", ReasonInvalidSpec, "path %q does not start with /", r.Path.Value)
	}
	switch r.Path.Type {
	case model.PathExact, model.PathPrefix:
	case model.PathTemplate:
		out.Segments = c.compileTemplate(b, r.Path.Value, captures)
	default:
		c.fail(b.Name, "", ReasonInvalidSpec, "unknown path type %q", r.Path.Type)
	}

	if len(r.Methods) > 0 {
		out.Methods = make(map[string]struct{}, len(r.Methods))
		for _, m := range r.Methods {
			if _, known := httpMethods[m]; !known {
				c.fail(b.Name, "", ReasonInvalidSpec, "unknown HTTP method %q", m)
				continue
			}
			if _, dup := out.Methods[m]; dup {
				c.fail(b.Name, "", ReasonInvalidSpec, "method %q is listed twice", m)
				continue
			}
			out.Methods[m] = struct{}{}
		}
	}
	return out
}

// compileTemplate splits a template into segments. A placeholder matches
// exactly one non-empty segment; the template covers the whole path.
func (c *blockCompiler) compileTemplate(b model.Block, value string, captures map[string]struct{}) []Segment {
	segments := strings.Split(strings.TrimPrefix(value, "/"), "/")
	out := make([]Segment, 0, len(segments))
	seen := map[string]struct{}{}
	for _, s := range segments {
		if !strings.HasPrefix(s, "{") || !strings.HasSuffix(s, "}") {
			out = append(out, Segment{Literal: s})
			continue
		}
		name := s[1 : len(s)-1]
		if !keyName.MatchString(name) {
			c.fail(b.Name, "", ReasonInvalidSpec, "placeholder %q does not match %s", name, keyName)
			continue
		}
		if name == model.KeyPath || name == model.KeyMethod || name == model.KeyClient || name == model.KeyToken {
			c.fail(b.Name, "", ReasonInvalidSpec, "placeholder %q collides with a built-in key", name)
			continue
		}
		if _, dup := seen[name]; dup {
			c.fail(b.Name, "", ReasonInvalidSpec, "placeholder %q repeats within one template", name)
			continue
		}
		seen[name] = struct{}{}
		if _, mapped := c.env.keys[name]; mapped {
			c.fail(b.Name, "", ReasonCaptureShadowsMappedKey,
				"capture %q shadows the mapped key of the same name inside this block", name)
		}
		captures[name] = struct{}{}
		out = append(out, Segment{Capture: name})
	}
	return out
}
