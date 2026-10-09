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
// claim path to show and a group to resolve.
func policy() model.Policy {
	return model.Policy{
		Domain:   domain,
		Mappings: []model.KeyMapping{{Key: "tenant", Claim: "org.id", Normalization: model.NormalizeLowercase}},
		Groups:   []model.Group{{Name: "partners", Values: []string{"zed", "bob", "alice"}}},
		Blocks: []model.Block{{
			Name: "api",
			Target: model.Target{Routes: []model.Route{{
				Path: model.PathMatch{Type: model.PathPrefix, Value: "/api/"},
			}}},
			Rules: []model.Rule{
				{Name: "partners",
					Matches:  []model.Predicate{{Key: model.KeySub, Operator: model.OperatorInGroup, Value: "partners"}},
					Counters: []string{model.KeySub},
					Rates:    []model.Rate{{Requests: 100, Period: time.Minute}}},
				{Name: "everyone", Rates: []model.Rate{{Requests: 1000, Period: time.Minute}}},
			},
		}},
	}
}

var appliedAt = time.Date(2026, 9, 21, 12, 0, 0, 0, time.UTC)

// ruleSet binds the policy at generation, with the UID uid-7, applied at
// appliedAt.
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

// fixture serves the handler of replica ratelimit-0 over a store that holds
// the policy at generation 7.
func fixture(t *testing.T) (http.Handler, *store.Store, *compile.Snapshot) {
	t.Helper()
	set, snapshot := ruleSet(t, 7)
	rules := store.New()
	rules.Replace(set)
	return debug.Handler(rules, "ratelimit-0"), rules, snapshot
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

// getDomain reads the JSON document of the fixture's domain.
func getDomain(t *testing.T) debug.DomainSnapshot {
	t.Helper()
	h, _, _ := fixture(t)
	rec := get(t, h, contract.SnapshotPath+"/"+domain, "")
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var doc debug.DomainSnapshot
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &doc))
	return doc
}

// The version is the one the management API reports, so the two listings
// compare by it. Replicas swap at different times, so the swap time sets one
// replica's report apart from another's.
func TestSummary_listsEveryDomainWithItsGeneration(t *testing.T) {
	h, rules, snapshot := fixture(t)

	rec := get(t, h, contract.SnapshotPath, "")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
	var summary debug.Summary
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &summary))
	assert.Equal(t, "ratelimit-0", summary.Replica)
	assert.WithinDuration(t, rules.SwappedAt(), summary.SwappedAt, 0, "the swap time of the store")
	assert.Equal(t, []debug.DomainSummary{{
		Domain:          domain,
		Generation:      7,
		UID:             "uid-7",
		AppliedAt:       appliedAt,
		RuleSetVersion:  ruleview.Version(snapshot),
		Blocks:          1,
		Rules:           2,
		DecisionBuckets: snapshot.DecisionBuckets,
		EffectiveKeys:   []string{"method", "path", "sub", "tenant"},
	}}, summary.Domains)
}

// The group is resolved: the rule shows the values the engine tests, sorted,
// not the group's name.
func TestDomain_rendersAGroupAsTheSortedValuesItResolvesTo(t *testing.T) {
	doc := getDomain(t)

	assert.Equal(t, int64(7), doc.Generation)
	require.Len(t, doc.Blocks, 1)
	require.Len(t, doc.Blocks[0].Rules, 2)
	assert.Equal(t, []ruleview.PredicateView{{Key: model.KeySub, Operator: "In", Values: []string{"alice", "bob", "zed"}}},
		doc.Blocks[0].Rules[0].Matches, "the matches of the rule partners")
}

// The keys carry the claim behind each one, which is the half of a "nobody is
// limited" question the rules alone cannot answer. The built-in sub is
// extracted first, then the mapped keys as authored.
func TestDomain_rendersTheClaimBehindEveryKey(t *testing.T) {
	doc := getDomain(t)

	require.Len(t, doc.Keys, 2)
	assert.Equal(t, model.KeySub, doc.Keys[0].Key, "the key extracted first")
	tenant := doc.Keys[1]
	assert.Equal(t, "tenant", tenant.Key)
	assert.Equal(t, "org.id", tenant.Claim)
	assert.Equal(t, string(model.NormalizeLowercase), tenant.Normalization)
}

func TestDomain_servesYAMLOnRequest(t *testing.T) {
	cases := []struct {
		name   string
		path   string
		accept string
	}{
		{"format=yaml in the query", contract.SnapshotPath + "/" + domain + "?format=yaml", ""},
		{"application/yaml in Accept", contract.SnapshotPath + "/" + domain, "application/yaml"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			h, _, _ := fixture(t)

			rec := get(t, h, c.path, c.accept)

			require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
			assert.Equal(t, "application/yaml", rec.Header().Get("Content-Type"))
			var doc debug.DomainSnapshot
			require.NoError(t, yaml.Unmarshal(rec.Body.Bytes(), &doc))
			assert.Equal(t, domain, doc.Domain)
			assert.Len(t, doc.Blocks, 1)
		})
	}
}

// The format parameter decides over the Accept header: format=json answers
// JSON whatever Accept names.
func TestDomain_servesJSONOnFormatJSONWhateverAcceptNames(t *testing.T) {
	h, _, _ := fixture(t)

	rec := get(t, h, contract.SnapshotPath+"/"+domain+"?format=json", "application/yaml")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// history is what a store held over a refusal: the set applied at generation
// 7, the same rules with a refusal of format version 9, and the set applied at
// generation 8 after it, compiled from currentSnapshot.
type history struct {
	older, refused, current *store.RuleSet
	currentSnapshot         *compile.Snapshot
}

func refusedThenApplied(t *testing.T) history {
	t.Helper()
	var h history
	rules := store.New()
	older, _ := ruleSet(t, 7)
	rules.Replace(older)
	h.older = rules.Load()
	rules.Refuse(&applied.Refusal{FormatVersion: 9, Reason: "unsupported"})
	h.refused = rules.Load()
	var newer *store.RuleSet
	newer, h.currentSnapshot = ruleSet(t, 8)
	rules.Replace(newer)
	h.current = rules.Load()
	return h
}

// The pairing the endpoint exists for: the rules, the generation they were
// applied from, and the refusal come off one rule set, so a document built
// from a set carries that set's facts and nothing of a set swapped in during
// the request. The refused reading rides on the set it left in place.
func TestSummarize_reportsARefusalWithTheGenerationOfTheSetItRidesOn(t *testing.T) {
	h := refusedThenApplied(t)

	summary := debug.Summarize(h.refused, "ratelimit-0")

	require.Len(t, summary.Domains, 1)
	assert.Equal(t, int64(7), summary.Domains[0].Generation)
	assert.Equal(t, &applied.Refusal{FormatVersion: 9, Reason: "unsupported"}, summary.Refusal)
	assert.Equal(t, h.older.SwappedAt(), summary.SwappedAt, "a refusal is not a swap")
}

// The applied set carries no refusal, whatever the reading before it.
func TestSummarize_reportsTheSetAppliedAfterARefusalWithoutIt(t *testing.T) {
	h := refusedThenApplied(t)

	summary := debug.Summarize(h.current, "ratelimit-0")

	require.Len(t, summary.Domains, 1)
	assert.Equal(t, int64(8), summary.Domains[0].Generation)
	assert.Equal(t, ruleview.Version(h.currentSnapshot), summary.Domains[0].RuleSetVersion)
	assert.Nil(t, summary.Refusal)
}

func TestRender_takesTheGenerationFromTheDomainItRenders(t *testing.T) {
	set, _ := ruleSet(t, 8)
	d, ok := set.Domain(domain)
	require.True(t, ok)

	doc := debug.Render(d)

	assert.Equal(t, int64(8), doc.Generation)
	assert.Equal(t, domain, doc.Domain)
	assert.Len(t, doc.Blocks, 1)
}

func TestDomain_isNotFoundForAnUnboundDomain(t *testing.T) {
	h, _, _ := fixture(t)

	rec := get(t, h, contract.SnapshotPath+"/gateway.nowhere", "")

	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// The endpoint reads the store and nothing else.
func TestHandler_refusesEveryMethodButGET(t *testing.T) {
	for _, method := range []string{http.MethodPost, http.MethodDelete, http.MethodPut} {
		t.Run(method, func(t *testing.T) {
			h, _, _ := fixture(t)
			req := httptest.NewRequest(method, contract.SnapshotPath+"/"+domain, nil)
			rec := httptest.NewRecorder()

			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
		})
	}
}
