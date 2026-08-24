package management

import (
	"context"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-logr/logr"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/events"

	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// Audit actions. They name what the operator did, not which endpoint served
// it, so a record survives a change of URL.
const (
	ActionResetCounters = "ResetCounters"
	ActionSetAudit      = "SetDecisionAudit"
)

// Audit outcomes.
const (
	OutcomeSucceeded = "succeeded"
	OutcomeRejected  = "rejected"
	OutcomeFailed    = "failed"
)

// AuditEvent is one management mutation, recorded whether it worked or not. A
// rejected reset is as interesting as a successful one: it is someone trying
// to lift a limit they could not name.
type AuditEvent struct {
	Action  string
	Subject Subject
	Outcome string

	Domain string
	RuleID string

	// Axes is the client selection, by axis name. Values identify a client, so
	// they are here for the same reason the endpoint accepts them: the record
	// has to say whose limit was lifted, or it answers nothing worth asking.
	Axes map[string]string

	// Keys is how many counters the action actually touched.
	Keys int

	// Reason explains a rejection or a failure.
	Reason string

	RequestID string
	Time      time.Time
}

// Auditor records management mutations.
type Auditor interface {
	Record(ctx context.Context, event AuditEvent)
}

// KubeAuditor writes each mutation to the operator log and, where it can, to a
// Kubernetes Event on the policy that owns the rule.
//
// The log line is the record that always happens: it is synchronous, it cannot
// be rate limited away, and it lands wherever the cluster ships logs. The
// Event is the one people find — it turns up under kubectl describe on the
// policy and gives a UI a history to read without this operator storing one.
// Events are aggregated and can be dropped under pressure, so they add reach,
// never assurance.
type KubeAuditor struct {
	Log logr.Logger

	// Recorder is optional. Without it only the log line is written.
	Recorder events.EventRecorder

	// Namespace is where the policy objects live, needed to address the Event
	// at one.
	Namespace string
}

// Record writes the audit trail for one mutation.
func (a *KubeAuditor) Record(_ context.Context, event AuditEvent) {
	if event.Time.IsZero() {
		event.Time = time.Now()
	}

	// The rule, the domain, and the axes came in on the request, and the reason
	// quotes them back. An audit trail the audited party can forge with a
	// newline is worth nothing, so every one of them is bounded and stripped of
	// control characters before it is recorded.
	fields := []any{
		"action", event.Action,
		"subject", logSafe(event.Subject.String()),
		"outcome", event.Outcome,
		"domain", logSafe(event.Domain),
		"rule", logSafe(event.RuleID),
		"keys", event.Keys,
		"requestId", event.RequestID,
		"time", event.Time.UTC().Format(time.RFC3339),
	}
	if len(event.Subject.Groups) > 0 {
		fields = append(fields, "subjectGroups", event.Subject.Groups)
	}
	if len(event.Axes) > 0 {
		fields = append(fields, "axes", formatAxes(event.Axes))
	}
	if event.Reason != "" {
		fields = append(fields, "reason", logSafe(event.Reason))
	}
	a.Log.Info("rate limit management mutation", fields...)

	a.recordEvent(event)
}

// recordEvent attaches the mutation to the policy that owns the rule, so it
// shows up where someone investigating that policy is already looking.
func (a *KubeAuditor) recordEvent(event AuditEvent) {
	if a.Recorder == nil || event.Outcome != OutcomeSucceeded {
		// A rejected call names an object that may not exist; the log carries
		// it and an Event on a missing object would go nowhere.
		return
	}
	policy, _, _, ok := splitRuleID(event.RuleID)
	if !ok {
		return
	}

	object := &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: policy, Namespace: a.Namespace},
	}
	message := "Reset " + plural(event.Keys, "counter") + " of rule " + logSafe(event.RuleID)
	if len(event.Axes) > 0 {
		message += " for " + formatAxes(event.Axes)
	}
	message += ", requested by " + logSafe(event.Subject.String())

	// The new events API separates the action taken from the reason it is
	// filed under, so the audit action supplies both halves rather than being
	// squeezed into one field.
	a.Recorder.Eventf(object, nil, corev1.EventTypeNormal, eventReason(event.Action), event.Action, "%s", message)
}

// eventReason maps an action to the CamelCase reason Kubernetes Events use.
func eventReason(action string) string {
	if action == "" {
		return "ManagementMutation"
	}
	return action
}

// formatAxes renders an axis selection in a stable order, so two records of
// the same selection read the same.
func formatAxes(axes map[string]string) string {
	names := make([]string, 0, len(axes))
	for name := range axes {
		names = append(names, name)
	}
	sort.Strings(names)

	// Axis values are claim values out of client tokens, so both halves of every
	// pair are attacker-chosen strings.
	var out strings.Builder
	for i, name := range names {
		if i > 0 {
			out.WriteString(", ")
		}
		out.WriteString(logSafe(name) + "=" + logSafe(axes[name]))
	}
	return out.String()
}

func plural(n int, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return strconv.Itoa(n) + " " + noun + "s"
}
