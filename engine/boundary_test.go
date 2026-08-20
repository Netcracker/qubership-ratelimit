package engine_test

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// forbidden lists the dependency roots that would turn the engine from a
// embeddable library into a part of the operator.
var forbidden = []string{
	"k8s.io/",
	"sigs.k8s.io/",
	"github.com/envoyproxy/",
	"google.golang.org/grpc",
}

// TestNoForbiddenDependencies keeps the module boundary honest. The module file
// already makes such an import fail to build; this test names the rule so the
// failure explains itself instead of surfacing as an unresolved package.
func TestNoForbiddenDependencies(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-test", "./...").Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			t.Fatalf("go list -deps -test: %v\n%s", err, exitErr.Stderr)
		}
		t.Fatalf("go list -deps -test: %v", err)
	}

	for dep := range strings.SplitSeq(strings.TrimSpace(string(out)), "\n") {
		for _, bad := range forbidden {
			if strings.HasPrefix(dep, bad) {
				t.Errorf("engine depends on %s; the operator module owns that layer", dep)
			}
		}
	}
}
