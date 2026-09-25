package debug_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
	engine "github.com/netcracker/qubership-ratelimit/engine"
	"github.com/netcracker/qubership-ratelimit/engine/compile"
	"github.com/netcracker/qubership-ratelimit/engine/model"
	"github.com/netcracker/qubership-ratelimit/engine/store/memory"
	"github.com/netcracker/qubership-ratelimit/service/internal/debug"
	"github.com/netcracker/qubership-ratelimit/service/internal/ruleview"
	"github.com/netcracker/qubership-ratelimit/service/internal/store"
)

const (
	domain    = "gateway.public"
	namespace = "core-1-core"
)

// policy declares a mapped key and a group, so that the rendering has a
// claim path to show and a client list to resolve.
func policy() model.Policy {
	return model.Policy{
		Domain:   domain,
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org.id", Normalization: model.NormalizeLowercase}},
		Groups:   []model.Group{{Name: "partners", Clients: []string{"zed", "bob", "alice"}}},
		Blocks: []model.Block{{
			Name: "api",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"},
			}}},
			Rules: []model.Rule{
				{Name: "partners",
					Matches:  []model.Predicate{{Key: model.KeyClient, Operator: model.OperatorInGroup, Value: "partners"}},
					Counters: []string{model.KeyClient},
					Rates:    []model.Rate{{Requests: 100, Period: time.Minute}}},
				{Name: "everyone", Rates: []model.Rate{{Requests: 1000, Period: time.Minute}}},
			},
		}},
	}
}

var appliedAt = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

func ruleSet(t *testing.T, generation int64) (*store.RuleSet, *compile.Snapshot) {
	t.Helper()
	p := policy()
	snapshot, problems := compile.Compile(namespace, domain, &p)
	require.Empty(t, problems, "broken fixture")
	return store.NewRuleSet(map[string]store.Domain{
		domain: {
			Engine: engine.New(snapshot, memory.New()), Snapshot: snapshot, Version: ruleview.Version(snapshot),
			Generation: generation, UID: "uid-7", AppliedAt: appliedAt,
		},
	}), snapshot
}

func fixture(t *testing.T) (http.Handler, *compile.Snapshot) {
	t.Helper()
	set, snapshot := ruleSet(t, 7)
	rules := store.New()
	rules.Replace(set)
	return debug.Handler(rules, "ratelimit-0"), snapshot
}

func get(t *testing.T, h http.Handler, path string, accept string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSummary_listsEveryDomainWithItsGeneration(t *testing.T) {
	h, snapshot := fixture(t)
	rec := get(t, h, contract.SnapshotPath, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var summary debug.Summary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &summary))
	assert.Equal(t, "ratelimit-0", summary.Replica)
	assert.False(t, summary.SwappedAt.IsZero(), "the swap time is what tells replicas apart")
	require.Len(t, summary.Domains, 1)
	row := summary.Domains[0]
	assert.Equal(t, domain, row.Domain)
	assert.Equal(t, int64(7), row.Generation)
	assert.Equal(t, "uid-7", row.UID)
	assert.Equal(t, appliedAt, row.AppliedAt)
	assert.Equal(t, ruleview.Version(snapshot), row.RuleSetVersion,
		"the version is the one the management API reports, so the two listings compare")
	assert.Equal(t, 1, row.Blocks)
	assert.Equal(t, 2, row.Rules)
	assert.Equal(t, snapshot.DecisionBuckets, row.DecisionBuckets)
	assert.Contains(t, row.EffectiveKeys, "tenant")
}

func TestDomain_rendersTheResolvedRulesAndTheClaimPaths(t *testing.T) {
	h, _ := fixture(t)
	rec := get(t, h, contract.SnapshotPath+"/"+domain, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var doc debug.DomainSnapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	assert.Equal(t, int64(7), doc.Generation)
	require.Len(t, doc.Blocks, 1)
	require.Len(t, doc.Blocks[0].Rules, 2)

	// The group is resolved: the rule shows the client list the engine
	// tests, sorted, not the group's name.
	partners := doc.Blocks[0].Rules[0]
	require.Len(t, partners.Matches, 1)
	assert.Equal(t, "In", partners.Matches[0].Operator)
	assert.Equal(t, []string{"alice", "bob", "zed"}, partners.Matches[0].Values)

	// The keys carry the claim behind each one, which is the half of a
	// "nobody is limited" question the rules alone cannot answer.
	var tenant *debug.KeyView
	for i := range doc.Keys {
		if doc.Keys[i].Key == "tenant" {
			tenant = &doc.Keys[i]
		}
	}
	require.NotNil(t, tenant, "the mapped key is missing from the extraction plan: %+v", doc.Keys)
	assert.Equal(t, "org.id", tenant.Claim)
	assert.Equal(t, string(model.NormalizeLowercase), tenant.Normalization)
	assert.Equal(t, model.KeyClient, doc.Keys[0].Key, "the built-in client is extracted first")
}

func TestDomain_answersYAMLOnRequest(t *testing.T) {
	h, _ := fixture(t)
	for name, rec := range map[string]*httptest.ResponseRecorder{
		"query":  get(t, h, contract.SnapshotPath+"/"+domain+"?format=yaml", ""),
		"accept": get(t, h, contract.SnapshotPath+"/"+domain, "application/yaml"),
	} {
		require.Equal(t, http.StatusOK, rec.Code, name)
		assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"), name)
		var doc debug.DomainSnapshot
		require.NoError(t, yaml.Unmarshal(rec.Body.Bytes(), &doc), name)
		assert.Equal(t, domain, doc.Domain, name)
		assert.Len(t, doc.Blocks, 1, name)
	}
}

// The pairing that the endpoint exists for: the rules, the generation they
// were applied from, and the refusal come off one rule set, so a document
// built from a set carries that set's facts and nothing of a set swapped in
// during the request.
func TestSummarize_pairsTheRulesWithTheGenerationOfTheSameSet(t *testing.T) {
	rules := store.New()
	older, _ := ruleSet(t, 7)
	rules.Replace(older)
	rules.Refuse(&applied.Refusal{FormatVersion: 9, Reason: "unsupported"})
	refused := rules.Load()
	newer, snapshot := ruleSet(t, 8)
	rules.Replace(newer)

	summary := debug.Summarize(refused, "ratelimit-0")
	require.Len(t, summary.Domains, 1)
	assert.Equal(t, int64(7), summary.Domains[0].Generation)
	require.NotNil(t, summary.Refusal, "the refused reading rides on the set it left in place")
	assert.Equal(t, 9, summary.Refusal.FormatVersion)
	assert.Equal(t, older.SwappedAt(), summary.SwappedAt, "a refusal is not a swap")

	summary = debug.Summarize(rules.Load(), "ratelimit-0")
	require.Len(t, summary.Domains, 1)
	assert.Equal(t, int64(8), summary.Domains[0].Generation)
	assert.Equal(t, ruleview.Version(snapshot), summary.Domains[0].RuleSetVersion)
	assert.Nil(t, summary.Refusal, "the applied set carries no refusal, whatever the reading before it")

	d, ok := newer.Domain(domain)
	require.True(t, ok)
	doc := debug.Render(d)
	assert.Equal(t, int64(8), doc.Generation)
	assert.Equal(t, domain, doc.Domain)
	assert.Len(t, doc.Blocks, 1)
}

func TestDomain_isNotFoundForAnUnboundDomain(t *testing.T) {
	h, _ := fixture(t)
	rec := get(t, h, contract.SnapshotPath+"/gateway.nowhere", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandler_refusesEveryMethodButGET(t *testing.T) {
	h, _ := fixture(t)
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		req := httptest.NewRequest(method, contract.SnapshotPath+"/"+domain, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusMethodNotAllowed, rec.Code, method)
	}
}
