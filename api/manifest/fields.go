package manifest

import (
	"encoding"
	"encoding/json"
	"reflect"
	"sort"
	"strings"
)

// FieldPaths lists the JSON paths of every field a type can carry, sorted:
// nested structs by dot, slice and array elements as [], map values as {}.
// Pointers and interfaces are looked through; a type met again on the way
// down is cut with "..." rather than followed, so a recursive type ends.
//
// It is what the payload's golden is made of. The bump check on the manifest
// cannot see a field added to the spec: the manifest golden does not move,
// and a payload sample would not move either when the new field is optional
// and omitted. The field set does move, and an older service meeting the new
// field would refuse the payload as malformed under a version it believes it
// supports. So the field set of the spec is pinned per format version, and a
// field added, removed, or renamed fails until FormatVersion moves.
func FieldPaths(t reflect.Type) []string {
	var paths []string
	walk(t, "", map[reflect.Type]bool{}, &paths)
	sort.Strings(paths)
	return paths
}

func walk(t reflect.Type, prefix string, seen map[reflect.Type]bool, paths *[]string) {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Interface {
		if t.Kind() == reflect.Interface {
			*paths = append(*paths, prefix+"<any>")
			return
		}
		t = t.Elem()
	}
	if hasOwnJSON(t) {
		*paths = append(*paths, prefix)
		return
	}
	switch t.Kind() {
	case reflect.Struct:
		if seen[t] {
			*paths = append(*paths, prefix+"...")
			return
		}
		seen[t] = true
		defer delete(seen, t)
		for f := range t.Fields() {
			// An unexported embedded struct is inlined by encoding/json, its
			// exported fields promoted; an unexported named field is not.
			if !f.IsExported() && !f.Anonymous {
				continue
			}
			name, inline := jsonName(f)
			if name == "-" {
				continue
			}
			if inline {
				walk(f.Type, prefix, seen, paths)
				continue
			}
			child := name
			if prefix != "" {
				child = prefix + "." + name
			}
			if isLeaf(f.Type) {
				*paths = append(*paths, child)
				continue
			}
			walk(f.Type, child, seen, paths)
		}
	case reflect.Slice, reflect.Array:
		if isLeaf(t.Elem()) {
			*paths = append(*paths, prefix+"[]")
			return
		}
		walk(t.Elem(), prefix+"[]", seen, paths)
	case reflect.Map:
		if isLeaf(t.Elem()) {
			*paths = append(*paths, prefix+"{}")
			return
		}
		walk(t.Elem(), prefix+"{}", seen, paths)
	default:
		*paths = append(*paths, prefix)
	}
}

var (
	jsonMarshaler = reflect.TypeFor[json.Marshaler]()
	textMarshaler = reflect.TypeFor[encoding.TextMarshaler]()
)

// isLeaf reports a type that has no fields of its own to descend into: a
// scalar, or a type with a JSON form of its own. A json.Marshaler or a
// TextMarshaler (metav1.Duration, resource.Quantity) is a struct of
// unexported fields to a walk, so it would contribute nothing and a field of
// that type would be absent from the golden, its addition unseen. Its JSON is
// whatever it writes, one value, so it is one path.
func isLeaf(t reflect.Type) bool {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if hasOwnJSON(t) {
		return true
	}
	switch t.Kind() {
	case reflect.Struct, reflect.Slice, reflect.Array, reflect.Map, reflect.Interface:
		return false
	}
	return true
}

// hasOwnJSON reports a type that encoding/json hands its own encoding to,
// through a value or a pointer receiver.
func hasOwnJSON(t reflect.Type) bool {
	p := reflect.PointerTo(t)
	return t.Implements(jsonMarshaler) || p.Implements(jsonMarshaler) ||
		t.Implements(textMarshaler) || p.Implements(textMarshaler)
}

// jsonName is the field's key in JSON and whether it is inlined: the tag's
// name when set, the Go name otherwise; an anonymous struct field without a
// name in its tag is inlined the way encoding/json inlines it.
func jsonName(f reflect.StructField) (name string, inline bool) {
	tag := f.Tag.Get("json")
	name, _, _ = strings.Cut(tag, ",")
	if name == "" {
		if f.Anonymous {
			return "", true
		}
		return f.Name, false
	}
	return name, false
}
