package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// MaxSelectedRules bounds how many rules may stream at once. The bound is not
// about memory — it is that "select everything" is the mistake this feature
// invites, and a limit makes an operator name what they are debugging.
const MaxSelectedRules = 64

// RuleRef names one rule of one domain.
type RuleRef struct {
	Domain string `json:"domain"`

	// RuleID is "policy/block/rule", the same identity the rule listing and
	// the counter listing report.
	RuleID string `json:"ruleId"`
}

// Selection is the set of rules whose decisions are streamed.
type Selection struct {
	Rules []RuleRef `json:"rules"`
}

// Normalize sorts and deduplicates the selection so that two ways of writing
// the same set are stored and reported identically.
func (s Selection) Normalize() Selection {
	seen := make(map[RuleRef]struct{}, len(s.Rules))
	out := make([]RuleRef, 0, len(s.Rules))
	for _, rule := range s.Rules {
		if _, duplicate := seen[rule]; duplicate {
			continue
		}
		seen[rule] = struct{}{}
		out = append(out, rule)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Domain != out[j].Domain {
			return out[i].Domain < out[j].Domain
		}
		return out[i].RuleID < out[j].RuleID
	})
	return Selection{Rules: out}
}

// Switchboard answers, on the decision path, whether a rule is streamed.
//
// Reads are a map lookup behind an atomic load: this is asked once per applied
// rule per request, so it sits in the hot path even when the answer is always
// no.
type Switchboard struct {
	current atomic.Pointer[selectionState]
}

type selectionState struct {
	selection Selection
	enabled   map[RuleRef]struct{}
}

// NewSwitchboard returns a switchboard with nothing selected.
func NewSwitchboard() *Switchboard {
	s := &Switchboard{}
	s.Set(Selection{})
	return s
}

// Enabled reports whether this rule's decisions are streamed.
func (s *Switchboard) Enabled(domain, policy, block, rule string) bool {
	state := s.current.Load()
	if state == nil || len(state.enabled) == 0 {
		return false
	}
	_, ok := state.enabled[RuleRef{Domain: domain, RuleID: policy + "/" + block + "/" + rule}]
	return ok
}

// Any reports whether anything at all is selected, so a caller can skip work
// that only matters when something is.
func (s *Switchboard) Any() bool {
	state := s.current.Load()
	return state != nil && len(state.enabled) > 0
}

// Selection returns the current selection.
func (s *Switchboard) Selection() Selection {
	state := s.current.Load()
	if state == nil {
		return Selection{Rules: []RuleRef{}}
	}
	return state.selection
}

// Set replaces the selection.
func (s *Switchboard) Set(selection Selection) {
	selection = selection.Normalize()
	if selection.Rules == nil {
		selection.Rules = []RuleRef{}
	}
	enabled := make(map[RuleRef]struct{}, len(selection.Rules))
	for _, rule := range selection.Rules {
		enabled[rule] = struct{}{}
	}
	s.current.Store(&selectionState{selection: selection, enabled: enabled})
}

// ConfigMapName is where the selection is persisted.
const ConfigMapName = "ratelimit-decision-audit"

// configMapKey is the entry inside it.
const configMapKey = "selection.json"

// Store persists the selection in a ConfigMap.
//
// It is shared state on purpose. Every replica decides, so a selection that
// lived in one process would stream a share of the traffic and leave an
// operator wondering why their rule looks quiet. A ConfigMap is also what
// makes the selection survive a restart, which matters because the feature is
// used while chasing something intermittent.
type Store struct {
	Client    client.Client
	Namespace string
	Labels    map[string]string
}

// Load reads the selection. A missing ConfigMap is the normal empty state, not
// an error: nothing is selected until someone selects it.
func (s *Store) Load(ctx context.Context) (Selection, error) {
	var configMap corev1.ConfigMap
	key := types.NamespacedName{Namespace: s.Namespace, Name: ConfigMapName}
	if err := s.Client.Get(ctx, key, &configMap); err != nil {
		if apierrors.IsNotFound(err) {
			return Selection{}, nil
		}
		return Selection{}, fmt.Errorf("read %s: %w", ConfigMapName, err)
	}

	raw, ok := configMap.Data[configMapKey]
	if !ok || raw == "" {
		return Selection{}, nil
	}
	var selection Selection
	if err := json.Unmarshal([]byte(raw), &selection); err != nil {
		return Selection{}, fmt.Errorf("decode %s/%s: %w", ConfigMapName, configMapKey, err)
	}
	return selection.Normalize(), nil
}

// Save writes the selection, creating the ConfigMap when it does not exist.
func (s *Store) Save(ctx context.Context, selection Selection) error {
	encoded, err := json.Marshal(selection.Normalize())
	if err != nil {
		return fmt.Errorf("encode the selection: %w", err)
	}

	desired := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      ConfigMapName,
			Namespace: s.Namespace,
			Labels:    s.Labels,
		},
		Data: map[string]string{configMapKey: string(encoded)},
	}

	var existing corev1.ConfigMap
	key := types.NamespacedName{Namespace: s.Namespace, Name: ConfigMapName}
	switch err := s.Client.Get(ctx, key, &existing); {
	case apierrors.IsNotFound(err):
		if err := s.Client.Create(ctx, desired); err != nil {
			return fmt.Errorf("create %s: %w", ConfigMapName, err)
		}
		return nil
	case err != nil:
		return fmt.Errorf("read %s: %w", ConfigMapName, err)
	}

	existing.Data = desired.Data
	if err := s.Client.Update(ctx, &existing); err != nil {
		return fmt.Errorf("update %s: %w", ConfigMapName, err)
	}
	return nil
}

// DefaultRefreshInterval is how long a replica may keep enforcing a stale
// selection. Turning the stream on is a debugging action taken by someone
// watching, so seconds are fine and a watch would cost an informer for one
// small object.
const DefaultRefreshInterval = 10 * time.Second

// Refresher keeps a replica's switchboard in step with the stored selection.
type Refresher struct {
	Store       *Store
	Switchboard *Switchboard
	Interval    time.Duration
	Log         logr.Logger
}

// NeedLeaderElection reports false: every replica decides, so every replica
// needs the selection.
func (r *Refresher) NeedLeaderElection() bool { return false }

// Start polls until ctx is cancelled.
func (r *Refresher) Start(ctx context.Context) error {
	interval := r.Interval
	if interval <= 0 {
		interval = DefaultRefreshInterval
	}

	r.refresh(ctx)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			r.refresh(ctx)
		}
	}
}

func (r *Refresher) refresh(ctx context.Context) {
	selection, err := r.Store.Load(ctx)
	if err != nil {
		// Keep the selection this replica already has. Losing the audit
		// stream is not worth a restart, and the next tick tries again.
		r.Log.Error(err, "failed to read the decision audit selection, keeping the current one")
		return
	}
	before := len(r.Switchboard.Selection().Rules)
	r.Switchboard.Set(selection)
	if after := len(selection.Rules); after != before {
		r.Log.Info("decision audit selection changed", "rules", after)
	}
}
