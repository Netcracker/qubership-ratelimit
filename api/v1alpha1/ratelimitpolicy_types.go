package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PathMatchType selects how the value of a route path is compared with the
// request path.
// +kubebuilder:validation:Enum=Exact;Prefix;Template
type PathMatchType string

const (
	// PathMatchExact compares the whole path, byte for byte.
	PathMatchExact PathMatchType = "Exact"

	// PathMatchPrefix compares the leading bytes of the path.
	PathMatchPrefix PathMatchType = "Prefix"

	// PathMatchTemplate compares segment by segment, where {name} matches
	// exactly one non-empty segment and becomes a descriptor key.
	PathMatchTemplate PathMatchType = "Template"
)

// BlockMode selects how the rules of one block combine.
// +kubebuilder:validation:Enum=All;FirstMatch
type BlockMode string

const (
	// BlockModeAll applies every matched rule of the block.
	BlockModeAll BlockMode = "All"

	// BlockModeFirstMatch applies the first matched rule in list order, which
	// makes the order of the list part of the meaning.
	BlockModeFirstMatch BlockMode = "FirstMatch"
)

// RuleBehavior selects what a matched rule does with the verdict.
// +kubebuilder:validation:Enum=Enforce;Shadow;Bypass
type RuleBehavior string

const (
	// RuleBehaviorEnforce counts the request and can reject it.
	RuleBehaviorEnforce RuleBehavior = "Enforce"

	// RuleBehaviorShadow counts the request and records metrics but never
	// rejects, and in a FirstMatch block it does not end the cascade. It is how
	// a tighter limit is tried out over a live one.
	RuleBehaviorShadow RuleBehavior = "Shadow"

	// RuleBehaviorBypass ends the cascade of its own block with a pass and never
	// touches the counter store. Other blocks still apply.
	RuleBehaviorBypass RuleBehavior = "Bypass"
)

// Algorithm selects how one rate entry counts its window. Each entry is an
// independent bucket, so a rule can hold a smoothed short window next to a daily
// quota that resets.
// +kubebuilder:validation:Enum=GCRA;FixedWindow
type Algorithm string

const (
	// AlgorithmGCRA meters requests at a steady rate with a burst allowance.
	AlgorithmGCRA Algorithm = "GCRA"

	// AlgorithmFixedWindow counts requests per wall-clock window and resets at
	// the boundary.
	AlgorithmFixedWindow Algorithm = "FixedWindow"
)

// PredicateOperator is a predicate over the value set of a key. A scalar key is
// a one-element set, an array key is the set of its elements, and a key the
// request does not carry is the empty set.
// +kubebuilder:validation:Enum=Equals;In;InGroup;Contains;Exists;NotExists
type PredicateOperator string

const (
	// OperatorEquals holds when the set equals {value}. It is rejected for an
	// array key.
	OperatorEquals PredicateOperator = "Equals"

	// OperatorIn holds when the set intersects values.
	OperatorIn PredicateOperator = "In"

	// OperatorInGroup holds when the set intersects the named group.
	OperatorInGroup PredicateOperator = "InGroup"

	// OperatorContains holds when value is a member of the set. It never means
	// substring.
	OperatorContains PredicateOperator = "Contains"

	// OperatorExists holds when the set is not empty.
	OperatorExists PredicateOperator = "Exists"

	// OperatorNotExists holds when the set is empty, which is how anonymous
	// traffic is selected. It means "the key is produced but absent from this
	// request", never "no one has heard of this key".
	OperatorNotExists PredicateOperator = "NotExists"
)

// HTTPMethod is one request method a route accepts.
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;PATCH;DELETE;CONNECT;OPTIONS;TRACE
type HTTPMethod string

// PathMatch selects request paths.
//
// The two rules below are written as one regex and four substring searches
// rather than as a walk over self.value.split('/'): the CRD cost estimator
// budgets each rule against the declared MaxLength, and the segment walk exceeds
// that budget by 2.5x. Placeholder names are checked for uniqueness by the
// compiler, which the estimator rejects here for the same reason.
// +kubebuilder:validation:XValidation:rule="self.type != 'Template' || self.value.matches('^(/([^/{}]+|[{][a-z][a-z0-9_]*[}]))+/?$')",message="in a Template every segment is either a literal without braces or one whole placeholder {name}, where name matches ^[a-z][a-z0-9_]*$"
// +kubebuilder:validation:XValidation:rule="self.type != 'Template' || !(self.value.contains('{path}') || self.value.contains('{method}') || self.value.contains('{token}') || self.value.contains('{client}'))",message="a Template placeholder cannot take the name of a built-in key: path, method, token, client"
type PathMatch struct {
	// Type selects how Value is compared.
	Type PathMatchType `json:"type"`

	// Value is the path, the prefix, or the template. It starts with a slash;
	// the query string of a request is cut before matching, so it never appears
	// here.
	// +kubebuilder:validation:Pattern=`^/`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Value string `json:"value"`
}

// Route selects request traffic for a block. The fields of one route combine
// with AND; the routes of a target combine with OR.
// +kubebuilder:validation:XValidation:rule="!has(self.methods) || self.methods.all(m, self.methods.filter(x, x == m).size() == 1)",message="the methods of a route are unique"
type Route struct {
	// Path selects request paths.
	Path PathMatch `json:"path"`

	// Methods accepts a request whose method is one of the listed values. An
	// absent list accepts any method.
	// +optional
	// +kubebuilder:validation:MaxItems=9
	// +listType=atomic
	Methods []HTTPMethod `json:"methods,omitempty"`
}

// Target restricts a block to part of the traffic of its domain.
type Target struct {
	// Routes is an OR-list. A block without a target sees the whole domain.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=16
	// +listType=atomic
	Routes []Route `json:"routes"`
}

// Predicate is one condition on the identity of the caller. Paths and methods
// belong in the target of the block, so a predicate cannot name them.
// +kubebuilder:validation:XValidation:rule="!(self.key in ['path', 'method', 'token'])",message="path and method are selected by target.routes, and token is an input rather than a key; none of them can appear in when"
// +kubebuilder:validation:XValidation:rule="!(self.operator in ['Equals', 'InGroup', 'Contains']) || (has(self.value) && !has(self.values))",message="operators Equals, InGroup and Contains take value and reject values"
// +kubebuilder:validation:XValidation:rule="self.operator != 'In' || (has(self.values) && !has(self.value))",message="operator In takes values and rejects value"
// +kubebuilder:validation:XValidation:rule="!(self.operator in ['Exists', 'NotExists']) || (!has(self.value) && !has(self.values))",message="operators Exists and NotExists take neither value nor values"
type Predicate struct {
	// Key names the descriptor key the predicate reads.
	// +kubebuilder:validation:Pattern=`^[a-z][a-z0-9_]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Key string `json:"key"`

	// Operator is the predicate applied to the value set of the key.
	Operator PredicateOperator `json:"operator"`

	// Value is the operand of Equals, Contains, and InGroup. For InGroup it is
	// the name of a group.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	Value string `json:"value,omitempty"`

	// Values is the operand of In.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +kubebuilder:validation:items:MaxLength=253
	// +listType=atomic
	Values []string `json:"values,omitempty"`
}

// Rate is one counting window of a rule. Windows of a rule are independent
// buckets, so a rate limit and a quota live side by side.
// +kubebuilder:validation:XValidation:rule="!has(self.burst) || self.algorithm == 'GCRA'",message="burst is a GCRA parameter; FixedWindow entries reject it"
// +kubebuilder:validation:XValidation:rule="self.period == '1d' || (duration(self.period) >= duration('1s') && duration(self.period) <= duration('24h'))",message="period ranges from 1s to 1d"
type Rate struct {
	// Requests is the quota of the window.
	// +kubebuilder:validation:Minimum=1
	Requests int32 `json:"requests"`

	// Period is the length of the window, written as one unit: 30s, 5m, 1h, 1d.
	// +kubebuilder:validation:Pattern=`^[1-9][0-9]*(s|m|h|d)$`
	// +kubebuilder:validation:MaxLength=8
	Period string `json:"period"`

	// Burst is the bucket depth of a GCRA window. It defaults to Requests,
	// which is a full bucket.
	// +optional
	// +kubebuilder:validation:Minimum=1
	Burst *int32 `json:"burst,omitempty"`

	// Algorithm is a property of the window rather than of the rule.
	// +kubebuilder:default=GCRA
	Algorithm Algorithm `json:"algorithm,omitempty"`
}

// Rule is one counter of a block.
// +kubebuilder:validation:XValidation:rule="self.behavior == 'Bypass' ? !has(self.rates) : (has(self.rates) && size(self.rates) > 0)",message="a rule with behavior Bypass carries no rates; every other rule carries at least one"
// +kubebuilder:validation:XValidation:rule="!has(self.rates) || self.rates.all(r, self.rates.filter(other, other.period == r.period).size() == 1)",message="the periods of a rule are unique"
type Rule struct {
	// Name is unique within its block and is part of the counter key.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// When is a conjunction of predicates. An empty list matches every request
	// the block sees.
	// +optional
	// +kubebuilder:validation:MaxItems=8
	// +listType=atomic
	When []Predicate `json:"when,omitempty"`

	// Counters are the axes of the bucket. An empty list gives the rule a
	// single shared bucket. A rule whose axis the request does not carry, such
	// as client for an anonymous caller, does not match: there is nothing to
	// key the bucket by.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +kubebuilder:validation:items:Pattern=`^[a-z][a-z0-9_]*$`
	// +kubebuilder:validation:items:MaxLength=63
	// +listType=atomic
	Counters []string `json:"counters,omitempty"`

	// Rates are the counting windows of the rule.
	// +optional
	// +kubebuilder:validation:MaxItems=4
	// +listType=atomic
	Rates []Rate `json:"rates,omitempty"`

	// Behavior selects what the rule does with the verdict.
	// +kubebuilder:default=Enforce
	Behavior RuleBehavior `json:"behavior,omitempty"`

	// Replaces silences rules of the same block, which is how a narrow rule
	// overrides a broad one. It is available only in an All block, where the
	// order of the list carries no meaning of its own.
	// +optional
	// +kubebuilder:validation:MaxItems=16
	// +kubebuilder:validation:items:MaxLength=63
	// +listType=atomic
	Replaces []string `json:"replaces,omitempty"`
}

// LimitBlock is a target plus the rules that count the traffic it selects.
// Blocks always add up: a request that lands in several blocks has to fit the
// verdict of each.
// +kubebuilder:validation:XValidation:rule="self.mode != 'FirstMatch' || self.rules.all(r, !has(r.replaces))",message="replaces needs mode All; in a FirstMatch block the order of the rules already decides"
// +kubebuilder:validation:XValidation:rule="self.mode == 'FirstMatch' || self.rules.all(r, r.behavior != 'Bypass' || (has(r.replaces) && size(r.replaces) > 0))",message="a Bypass rule in an All block names the rules it exempts from in replaces; without them it is a silent no-op"
type LimitBlock struct {
	// Name is unique within its policy and is part of the counter key.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Target restricts the block. An absent target lets the block see the whole
	// domain.
	// +optional
	Target *Target `json:"target,omitempty"`

	// Mode selects how the rules of the block combine. It has no effect across
	// blocks.
	// +kubebuilder:default=All
	Mode BlockMode `json:"mode,omitempty"`

	// Rules are the counters of the block.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=128
	// +listType=map
	// +listMapKey=name
	Rules []Rule `json:"rules"`
}

// RateLimitPolicySpec is a set of rate limit rules bound to one domain.
type RateLimitPolicySpec struct {
	// Domain binds this policy to a traffic source. It has to equal, byte for
	// byte, the domain the rate limit filter of that gateway sends. Comparison
	// is case-sensitive.
	//
	// A colon separates the segments of a counter key, and braces are Redis
	// Cluster hash tags that decide slot routing, so neither is allowed here.
	// The naming convention is <kind>.<name>: gateway.public, service.billing.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Domain string `json:"domain"`

	// Groups are the client lists private to this policy. A name defined here
	// shadows a group of the same name in the mapping of the domain.
	// +optional
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Groups []ClientGroup `json:"groups,omitempty"`

	// Limits are the blocks of the policy.
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:MaxItems=64
	// +listType=map
	// +listMapKey=name
	Limits []LimitBlock `json:"limits"`
}

// RuleProblem describes what is wrong with one rule. Problems live outside
// conditions because conditions are a map keyed by type, and a policy can hold
// several problems at once.
//
// The list carries root causes only, never the cascade of every rule in an
// invalid policy: the author needs the reference that does not resolve, not a
// restatement of the atomicity rule once per rule.
type RuleProblem struct {
	// Block names the block the rule belongs to.
	Block string `json:"block"`

	// Rule names the rule.
	Rule string `json:"rule"`

	// Reason is one of the Problem constants of this package.
	Reason string `json:"reason"`

	// Message says what the rule references and what the domain offers.
	// +optional
	Message string `json:"message,omitempty"`
}

// RateLimitPolicyStatus is the observed state of a RateLimitPolicy.
type RateLimitPolicyStatus struct {
	// GenerationStatus reports which generation is enforced. Zero for
	// ActiveGeneration means the policy contributes no rules at all: its latest
	// generation is invalid and there is no earlier one to fall back to.
	GenerationStatus `json:",inline"`

	// Conditions holds the latest observations of the policy state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Problems is the length of RuleProblems, which a printer column can show
	// and a JSONPath expression cannot compute.
	// +optional
	Problems int32 `json:"problems,omitempty"`

	// RuleProblems lists the diagnostics of the latest generation. A blocking
	// entry invalidates that generation whole: Ready goes false with a reason,
	// and an earlier generation keeps running where there is one. An
	// informational entry, such as CaptureShadowsMappedKey, leaves Ready alone —
	// a fact to alert on rather than a failure of the object.
	// +optional
	// +kubebuilder:validation:MaxItems=256
	// +listType=atomic
	RuleProblems []RuleProblem `json:"ruleProblems,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=ratelimit,shortName=rlp
// +kubebuilder:printcolumn:name="Domain",type=string,JSONPath=`.spec.domain`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Problems",type=integer,JSONPath=`.status.problems`
// +kubebuilder:printcolumn:name="Active",type=integer,JSONPath=`.status.activeGeneration`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// RateLimitPolicy is a set of rate limit rules bound to one gateway domain.
//
// Policies are units of ownership and review rather than units of evaluation:
// every event recompiles the whole domain, and after compilation there are no
// policies left, only one flat set of blocks.
//
// A generation is enforced whole or not at all. That makes the layout of a
// namespace a design choice: keep the safety-net total limits in a small policy
// of their own, over built-in keys, where they can hardly ever become invalid.
type RateLimitPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitPolicySpec   `json:"spec,omitempty"`
	Status RateLimitPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// RateLimitPolicyList contains a list of RateLimitPolicy.
type RateLimitPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimitPolicy `json:"items"`
}
