package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// PathMatchType selects how the value of a route path is compared with the
// request path.
// +kubebuilder:validation:Enum=Exact;Prefix;Template
type PathMatchType string

const (
	// PathMatchExact compares the whole path, byte for byte, with the query
	// already stripped. There is no normalization: /quotes and /quotes/ are
	// different paths.
	PathMatchExact PathMatchType = "Exact"

	// PathMatchPrefix compares the leading segments of the path. The match
	// ends at the end of the path or at a slash, so /api/v1/orders covers
	// /api/v1/orders/42 but not /api/v1/orders-archive.
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
// +kubebuilder:validation:Enum=Equals;In;InGroup;Contains;Exists;DoesNotExist
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

	// OperatorDoesNotExist holds when the set is empty, which is how anonymous
	// traffic is selected. It means "the key is produced but absent from this
	// request", never "no one has heard of this key".
	OperatorDoesNotExist PredicateOperator = "DoesNotExist"
)

// HTTPMethod is one request method a route accepts.
// +kubebuilder:validation:Enum=GET;HEAD;POST;PUT;PATCH;DELETE;CONNECT;OPTIONS;TRACE
type HTTPMethod string

// PathMatch selects request paths.
type PathMatch struct {
	// Type selects how Value is compared.
	Type PathMatchType `json:"type"`

	// Value is the path, the prefix, or the template. It starts with a slash;
	// the query string of a request is cut before matching, so it never appears
	// here.
	// +kubebuilder:validation:Pattern=`^/`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=2048
	Value string `json:"value"`
}

// Route selects request traffic for a block. The fields of one route combine
// with AND; the routes of a target combine with OR.
type Route struct {
	// Path selects request paths.
	Path PathMatch `json:"path"`

	// Methods accepts a request whose method is one of the listed values. An
	// absent list accepts any method.
	// +optional
	// +listType=set
	Methods []HTTPMethod `json:"methods,omitempty"`
}

// Target restricts a block to part of the traffic of its domain.
type Target struct {
	// Routes is an OR-list. A block without a target sees the whole domain.
	// +kubebuilder:validation:MinItems=1
	// +listType=atomic
	Routes []Route `json:"routes"`
}

// Predicate is one condition on the identity of the caller. Paths and methods
// belong in the target of the block, so a predicate cannot name them.
//
// The compiler checks the parameters against the operator and reports a
// mismatch as an InvalidSpec problem. It is not a CEL rule on the schema: the
// cost estimator charges every rule the product of the list bounds on the way
// to it, so keeping these checks at admission would mean bounding every list
// for the estimator's sake and maintaining a second copy of the compiler.
type Predicate struct {
	// Key names the descriptor key the predicate reads: client, a mappings
	// key, or a capture of the block's own Template routes.
	// +kubebuilder:validation:Pattern=`^[a-z][a-zA-Z0-9_]*$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Key string `json:"key"`

	// Operator is the predicate applied to the value set of the key.
	Operator PredicateOperator `json:"operator"`

	// Value is the operand of Equals, Contains, and InGroup. For InGroup it is
	// the name of a group.
	// +optional
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=256
	Value string `json:"value,omitempty"`

	// Values is the operand of In.
	// +optional
	// +kubebuilder:validation:MinItems=1
	// +kubebuilder:validation:items:MaxLength=256
	// +listType=atomic
	Values []string `json:"values,omitempty"`
}

// Rate is one counting window of a rule. Windows of a rule are independent
// buckets, so a rate limit and a quota live side by side.
type Rate struct {
	// Requests is the quota of the window.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	Requests int32 `json:"requests"`

	// PeriodSeconds is the length of the window. A day is the ceiling: beyond
	// it a counter stops being a rate limit and becomes an accounting record.
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=86400
	PeriodSeconds int32 `json:"periodSeconds"`

	// Burst is the bucket depth of a GCRA window. It defaults to Requests,
	// which is a full bucket, and a FixedWindow entry that sets it is rejected
	// by the compiler.
	// +optional
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=2147483647
	Burst *int32 `json:"burst,omitempty"`

	// Algorithm is a property of the window rather than of the rule.
	// +kubebuilder:default=GCRA
	Algorithm Algorithm `json:"algorithm,omitempty"`
}

// Rule is one counter of a block.
type Rule struct {
	// Name is unique within its block and is part of the counter key.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Name string `json:"name"`

	// Matches is a conjunction of predicates. An empty list matches every
	// request the block sees.
	// +optional
	// +listType=atomic
	Matches []Predicate `json:"matches,omitempty"`

	// Counters are the axes of the bucket. An empty list gives the rule a
	// single shared bucket. A rule whose axis the request does not carry, such
	// as client for an anonymous caller, does not match: there is nothing to
	// key the bucket by.
	// +optional
	// +kubebuilder:validation:items:Pattern=`^[a-z][a-zA-Z0-9_]*$`
	// +kubebuilder:validation:items:MaxLength=63
	// +listType=atomic
	Counters []string `json:"counters,omitempty"`

	// Rates are the counting windows of the rule, keyed by period. A rule with
	// behavior Bypass carries none; every other rule carries at least one.
	// +optional
	// +listType=map
	// +listMapKey=periodSeconds
	Rates []Rate `json:"rates,omitempty"`

	// Behavior selects what the rule does with the verdict.
	// +kubebuilder:default=Enforce
	Behavior RuleBehavior `json:"behavior,omitempty"`

	// ReplacedRules silences rules of the same block, which is how a narrow
	// rule overrides a broad one. It is available only in an All block, where
	// the order of the list carries no meaning of its own.
	// +optional
	// +kubebuilder:validation:items:MaxLength=63
	// +listType=atomic
	ReplacedRules []string `json:"replacedRules,omitempty"`
}

// LimitBlock is a target plus the rules that count the traffic it selects.
// Blocks always add up: a request that lands in several blocks has to fit the
// verdict of each.
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
	// +listType=map
	// +listMapKey=name
	Rules []Rule `json:"rules"`
}

// RateLimitPolicySpec is the whole rate limit configuration of one domain:
// how identity is read out of a token, which client groups exist, and which
// rules count the traffic.
type RateLimitPolicySpec struct {
	// Domain binds this policy to a traffic source. It has to equal, byte for
	// byte, the domain the rate limit filter of that gateway sends, and it
	// equals metadata.name. Comparison is case-sensitive.
	//
	// A colon separates the segments of a counter key, braces are Redis
	// Cluster hash tags that decide slot routing, and a slash separates the
	// namespace from the domain inside the tag, so none of them is allowed
	// here. The naming convention is <kind>.<name>: gateway.public,
	// service.billing.
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$`
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=63
	Domain string `json:"domain"`

	// Mappings declare which token claims become descriptor keys. An empty
	// list leaves the domain with its built-in keys, client among them.
	// +optional
	// +listType=map
	// +listMapKey=key
	Mappings []ClaimMapping `json:"mappings,omitempty"`

	// Groups are the named client lists the InGroup operator resolves against.
	// +optional
	// +listType=map
	// +listMapKey=name
	Groups []ClientGroup `json:"groups,omitempty"`

	// Limits are the blocks of the policy.
	// +kubebuilder:validation:MinItems=1
	// +listType=map
	// +listMapKey=name
	Limits []LimitBlock `json:"limits"`
}

// RuleProblem describes what is wrong with one rule. Problems live outside
// conditions because conditions are a map keyed by type, and a generation can
// hold several problems at once.
//
// The list carries root causes only, never the cascade of every rule in an
// invalid generation: the author needs the reference that does not resolve, not
// a restatement of the atomicity rule once per rule.
type RuleProblem struct {
	// Block names the block the rule belongs to. It is empty for a problem of
	// the policy as a whole, such as the decision budget.
	// +optional
	Block string `json:"block,omitempty"`

	// Rule names the rule, empty for a block-level or policy-level problem.
	// +optional
	Rule string `json:"rule,omitempty"`

	// Reason is one of the Problem constants of this package.
	Reason string `json:"reason"`

	// Message says what the rule references and what the domain offers.
	// +optional
	// +kubebuilder:validation:MaxLength=1024
	Message string `json:"message,omitempty"`
}

// ReplicaStatus is what the leader sees through the EndpointSlice of its own
// Service.
//
// "All replicas" means the ready endpoints at the time of the probe, not the
// Deployment's spec.replicas: a pod that is not ready receives no traffic and
// does not belong in the denominator.
type ReplicaStatus struct {
	// Total is the number of ready replicas at the time of the probe.
	// +optional
	Total int32 `json:"total"`

	// Applied is how many of them enforce ActiveGeneration.
	// +optional
	Applied int32 `json:"applied"`

	// LastCheckTime is the freshness of the probe. When no pod exists at all
	// there is nobody to write the status, and the age of this stamp is what
	// shows it.
	// +optional
	LastCheckTime *metav1.Time `json:"lastCheckTime,omitempty"`
}

// RateLimitPolicyStatus is the observed state of a RateLimitPolicy.
type RateLimitPolicyStatus struct {
	// ObservedGeneration is the latest spec generation the leader has seen.
	// +optional
	ObservedGeneration int64 `json:"observedGeneration,omitempty"`

	// ActiveGeneration is the generation actually being enforced. It falls
	// behind ObservedGeneration when the latest edit does not compile and the
	// last-good generation keeps running. Zero means the domain is unprotected:
	// no generation is in effect at all.
	// +optional
	ActiveGeneration int64 `json:"activeGeneration,omitempty"`

	// EffectiveKeys is the domain-wide key set of ActiveGeneration: the
	// built-in keys plus the mapped ones. Route captures are per block and do
	// not appear here. It reports what is in effect rather than what was asked
	// for, so a rule author reads the set their rules actually resolve against.
	// +optional
	// +listType=atomic
	EffectiveKeys []string `json:"effectiveKeys,omitempty"`

	// Replicas is what the leader observed about the fleet.
	// +optional
	Replicas ReplicaStatus `json:"replicas,omitempty"`

	// Conditions holds the latest observations of the policy state.
	// +optional
	// +listType=map
	// +listMapKey=type
	Conditions []metav1.Condition `json:"conditions,omitempty"`

	// Rules is how many rules the active generation contributes, which a
	// printer column can show and a JSONPath expression cannot compute.
	// +optional
	Rules int32 `json:"rules,omitempty"`

	// Problems is the length of RuleProblems, for the same reason.
	// +optional
	Problems int32 `json:"problems,omitempty"`

	// RuleProblems lists the diagnostics of the latest generation. A blocking
	// entry invalidates that generation whole: Accepted goes false, Ready goes
	// false with reason NotCompiled, and the last-good generation keeps running
	// where there is one. An informational entry, such as
	// CaptureShadowsMappedKey, leaves both alone — a fact to alert on rather
	// than a failure of the object.
	// +optional
	// +listType=atomic
	RuleProblems []RuleProblem `json:"ruleProblems,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:categories=ratelimit,shortName=rlp
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="Replicas",type=string,JSONPath=`.status.replicas.applied`
// +kubebuilder:printcolumn:name="Rules",type=integer,JSONPath=`.status.rules`
// +kubebuilder:printcolumn:name="Problems",type=integer,JSONPath=`.status.problems`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`
// +kubebuilder:validation:XValidation:rule="self.metadata.name == self.spec.domain",message="metadata.name has to equal spec.domain: the policy is the singleton of its domain"

// RateLimitPolicy is the whole rate limit configuration of one gateway domain.
//
// The singleton comes out of the naming rule rather than out of arbitration:
// metadata.name equals spec.domain, and object names are unique within a
// namespace, so a second policy for a domain cannot be created. The API server
// rejects it with AlreadyExists, and there is no "which one wins" question to
// answer.
//
// Everything the domain needs lives in this one object: the claim mapping, the
// groups, and the rules change in one edit and apply atomically, so a request
// never sees old extraction mixed with new rules. The compiler resolves the
// references from rules to keys and groups inside the object, with no
// cross-object arbitration anywhere.
//
// A generation is enforced whole or not at all. The API server checks only the
// shape — patterns, enums, ranges, duplicate names, and this name rule — while
// everything that relates fields to each other is judged by the compiler on
// every generation and answered through the status.
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
