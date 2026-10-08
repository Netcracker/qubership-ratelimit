//go:build e2e

package e2e

import (
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	"github.com/onsi/gomega/gstruct"

	corev1 "k8s.io/api/core/v1"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// The series asserted here are the contract the dashboard and the alerts are
// built on: a renamed metric or label would ship a dashboard full of empty
// panels, and this suite is where that breaks first. The split puts them on
// two scrapes: the service replicas carry the checks, the decisions, the
// applies, and the domain gauges, and traffic may land on any replica, so
// those assertions run against the union of every replica's scrape; the
// operator carries the policy status and the fleet, judged once, so those
// run against its scrape alone. Each chart ships a PodMonitor for its own
// pods behind MONITORING_ENABLED, which the e2e cluster does not set: the
// render is pinned by the chart tests, and the scrape by this suite.
var _ = Describe("the metrics endpoint", Ordered, Label("metrics"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-ratelimit"
		limit     = 2

		// The counter identity is block/rule: the policy is the singleton of
		// its domain, so its name adds nothing a bucket key needs.
		rule = "probe/per-path"
	)
	var (
		applied  bool
		window   time.Time
		families map[string]*dto.MetricFamily
		operator map[string]*dto.MetricFamily
	)

	BeforeAll(func() {
		// The fixture half runs once even across flake retries: the budget is
		// an hour long, so a retry that minted a fresh policy would find the
		// gateway un-warmable (every probe already refused) and a rule label
		// with no admissions behind it. Only the scrape is retried.
		if !applied {
			applied = true

			// Warmed before the policy exists: warm-up probes would come out
			// of the hour-long budget the burst below is about to spend.
			waitGatewayServes("public-gateway", probePath)
			Expect(apply(newPolicy(domain,
				prefixLimits(probePath, "per-path", []string{"path"}, limit, 3600)))).To(Succeed())
			waitApplied(domain)

			window = time.Now()
			codes := gatewayBurst("public-gateway", probePath, limit+2, nil)
			Expect(codes).To(ContainElement(429), "the burst never hit the limit; codes: %v", codes)
		}

		families = scrapeAllReplicas()
		holder := leaseHolderPod()
		Expect(holder).NotTo(BeEmpty(), "no operator pod holds the lease")
		operator = scrapePod(holder)
	})
	AfterAll(func() {
		if applied {
			deletePolicies(domain)
		}
	})

	It("counts checks by domain and verdict", func() {
		Expect(seriesLabels(families, "ratelimit_checks_total")).To(ContainElements(
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"domain": Equal(domain), "verdict": Equal("ok")}),
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"domain": Equal(domain), "verdict": Equal("over_limit")}),
		), "the scrape carries no admitted or no refused checks of %s", domain)
	})

	It("attributes the refusal to its block/rule identity", func() {
		Expect(seriesLabels(families, "ratelimit_decisions_total")).To(ContainElement(
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{
				"domain": Equal(domain), "outcome": Equal("over_limit"), "rule": Equal(rule),
			})), "the scrape does not attribute the refusal to %s", rule)
	})

	It("counts the near-limit precursor", func() {
		Expect(seriesLabels(families, "ratelimit_near_limit_total")).To(ContainElement(
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"domain": Equal(domain), "rule": Equal(rule)})),
			"the scrape carries no near-limit precursor for %s", rule)
	})

	It("times checks with the filter-timeout boundary", func() {
		// The 50ms bucket is the boundary the gateway filter timeout sits on;
		// "p99 over the budget" reads exactly only while it exists.
		Expect(histogramBounds(families, "ratelimit_check_duration_seconds",
			map[string]string{"domain": domain})).To(ContainElement(0.05),
			"the check duration histogram lost its 0.05 bucket boundary")
	})

	It("counts the configurations applied", func() {
		Expect(seriesLabels(families, "ratelimit_snapshot_rebuilds_total")).To(ContainElement(
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"result": Equal("ok")})),
			"the scrape carries no successful apply")
	})

	It("reports the applied generation of the domain", func() {
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		Expect(gaugeValue(families, "ratelimit_policy_applied_generation",
			map[string]string{"domain": domain})).To(Equal(float64(p.Status.ActiveGeneration)),
			"the service's scrape does not report the generation it enforces")
	})

	It("reports the policy ready on the operator's scrape", func() {
		// Ready is the fleet's judgement, taken a probe cycle after the
		// replicas applied the generation: the first scrape can still read
		// the rollout in flight, so the series is waited for, not read once.
		Eventually(func() float64 {
			operator = scrapePod(leaseHolderPod())
			return gaugeValue(operator, "ratelimit_policy_ready", map[string]string{"domain": domain, "reason": ""})
		}).WithTimeout(propagationTimeout).WithPolling(3*time.Second).Should(Equal(1.0),
			"the operator's scrape does not report %s ready", domain)
		// The same scrape carries the fleet behind the verdict, and the leader
		// gauge, since the operator holds the lease and its scrape has to say so.
		gauges := struct{ PolicyEnforced, PolicyReplicasApplied, Leader float64 }{
			PolicyEnforced: gaugeValue(operator, "ratelimit_policy_enforced", map[string]string{"domain": domain}),
			PolicyReplicasApplied: gaugeValue(operator, "ratelimit_policy_replicas",
				map[string]string{"domain": domain, "state": "applied"}),
			Leader: gaugeValue(operator, "ratelimit_leader", nil),
		}
		Expect(gauges).To(gstruct.MatchAllFields(gstruct.Fields{
			"PolicyEnforced":        Equal(1.0),
			"PolicyReplicasApplied": BeNumerically(">", 0),
			"Leader":                Equal(1.0),
		}), "the gauges of %s on the operator's scrape", domain)
	})

	It("gauges the domain facts", func() {
		facts := struct {
			DecisionBucketsSeries []map[string]string
			Blocks, Rules         float64
		}{
			DecisionBucketsSeries: seriesLabels(families, "ratelimit_domain_decision_buckets"),
			Blocks:                gaugeValue(families, "ratelimit_domain_blocks", map[string]string{"domain": domain}),
			Rules:                 gaugeValue(families, "ratelimit_domain_rules", map[string]string{"domain": domain}),
		}
		Expect(facts).To(gstruct.MatchAllFields(gstruct.Fields{
			"DecisionBucketsSeries": ContainElement(
				gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"domain": Equal(domain)})),
			"Blocks": Equal(1.0),
			"Rules":  Equal(1.0),
		}), "the domain gauges of %s on the service scrape", domain)
	})

	It("labels the extraction series by domain", func() {
		// Seeded at zero on apply: the series exists before any token
		// arrives, and it is the domain's, since a key is declared per
		// domain and a dead claim path is a fact about one domain's mapping.
		Expect(seriesLabels(families, "ratelimit_extractions_total")).To(ContainElement(
			gstruct.MatchKeys(gstruct.IgnoreExtras, gstruct.Keys{"domain": Equal(domain), "key": Equal("sub")})),
			"the scrape carries no seeded extraction series for the domain's built-in key")
	})

	// expectBuildInfo asserts the build info of one component's scrape: a
	// series of value 1 that names a version.
	expectBuildInfo := func(scrape map[string]*dto.MetricFamily, component string) {
		GinkgoHelper()
		series := seriesOf(scrape, "ratelimit_build_info", map[string]string{"component": component})
		Expect(series).NotTo(BeNil(), "the %s scrape carries no build info", component)
		Expect(series.GetGauge().GetValue()).To(Equal(1.0), "ratelimit_build_info on the %s scrape", component)
		Expect(labelsOf(series)).To(HaveKeyWithValue("version", Not(BeEmpty())),
			"the %s scrape names no version", component)
	}

	It("names its version on the service scrape", func() {
		expectBuildInfo(families, "service")
	})

	It("names its version on the operator scrape", func() {
		expectBuildInfo(operator, "operator")
	})

	It("carries the Go runtime series on the service scrape", func() {
		Expect(slices.Sorted(maps.Keys(families))).To(ContainElement("go_goroutines"),
			"the Go runtime series are not riding along on the service")
	})

	It("carries the Go runtime series on the operator scrape", func() {
		Expect(slices.Sorted(maps.Keys(operator))).To(ContainElement("go_goroutines"),
			"the Go runtime series are not riding along on the operator")
	})

	It("leaves the sampled refusal in the log", func() {
		Eventually(serviceLogsSince(window)).WithTimeout(30*time.Second).
			Should(ContainSubstring("rate limit refused domain="+domain),
				"no replica logged the sampled refusal line")
	})
})

// scrapeAllReplicas fetches /metrics from every running replica and merges
// the parses; a series is asserted against the union because the burst may
// have landed on any replica.
func scrapeAllReplicas() map[string]*dto.MetricFamily {
	pods := servicePods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to scrape")
	merged := map[string]*dto.MetricFamily{}
	for _, pod := range pods {
		mergeScrape(merged, pod)
	}
	return merged
}

// mergeScrape fetches /metrics from one pod over a port-forward and merges
// the parse into families. The port-forward goes through the kubelet rather
// than the pod network, so a scrape reads a pod that a mesh policy has
// silenced to its peers.
func mergeScrape(families map[string]*dto.MetricFamily, pod corev1.Pod) {
	port := namedPort(pod, "metrics")
	Expect(port).NotTo(BeZero(), "pod %s exposes no metrics port", pod.Name)

	addr, stop := forwardToPod(pod.Name, port)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Get("http://" + addr + "/metrics")
	if err != nil {
		stop()
		Fail(fmt.Sprintf("pod %s did not answer on /metrics: %v", pod.Name, err))
	}
	// The zero-value TextParser carries no name validation scheme and
	// panics on the first name it checks.
	parser := expfmt.NewTextParser(model.LegacyValidation)
	found, err := parser.TextToMetricFamilies(resp.Body)
	_ = resp.Body.Close()
	stop()
	Expect(err).NotTo(HaveOccurred(), "the scrape of %s does not parse", pod.Name)

	for name, family := range found {
		if have, ok := families[name]; ok {
			have.Metric = append(have.Metric, family.Metric...)
		} else {
			families[name] = family
		}
	}
}

// gaugeValue returns the value of the matching gauge series, NaN-free zero
// when there is none - the mismatch then reads as "not 1" rather than a
// panic.
func gaugeValue(families map[string]*dto.MetricFamily, name string, labels map[string]string) float64 {
	m := seriesOf(families, name, labels)
	if m == nil {
		return 0
	}
	return m.GetGauge().GetValue()
}

// counterSum adds up every series of the family that carries the given
// labels - counters arrive per replica, and the union is what a burst
// touched.
func counterSum(families map[string]*dto.MetricFamily, name string, labels map[string]string) float64 {
	family := families[name]
	if family == nil {
		return 0
	}
	total := 0.0
	for _, m := range family.Metric {
		if carries(m, labels) {
			total += m.GetCounter().GetValue()
		}
	}
	return total
}

// histogramBounds returns the bucket upper bounds of the matching histogram
// series, nil when there is none.
func histogramBounds(families map[string]*dto.MetricFamily, name string, labels map[string]string) []float64 {
	m := seriesOf(families, name, labels)
	if m == nil {
		return nil
	}
	bounds := make([]float64, 0, len(m.GetHistogram().GetBucket()))
	for _, b := range m.GetHistogram().GetBucket() {
		bounds = append(bounds, b.GetUpperBound())
	}
	return bounds
}

// seriesOf returns the first series of the family that carries the given
// labels, nil when there is none.
func seriesOf(families map[string]*dto.MetricFamily, name string, labels map[string]string) *dto.Metric {
	family := families[name]
	if family == nil {
		return nil
	}
	for _, m := range family.Metric {
		if carries(m, labels) {
			return m
		}
	}
	return nil
}

// seriesLabels returns the label set of every series of the family, nil when
// the scrape carries no such family. An assertion over it prints the series
// the scrape does carry.
func seriesLabels(families map[string]*dto.MetricFamily, name string) []map[string]string {
	family := families[name]
	if family == nil {
		return nil
	}
	sets := make([]map[string]string, 0, len(family.Metric))
	for _, m := range family.Metric {
		sets = append(sets, labelsOf(m))
	}
	return sets
}

// carries reports whether the series carries every given label pair.
func carries(m *dto.Metric, labels map[string]string) bool {
	carried := labelsOf(m)
	for k, v := range labels {
		if carried[k] != v {
			return false
		}
	}
	return true
}

// labelsOf returns the label pairs of one series.
func labelsOf(m *dto.Metric) map[string]string {
	carried := make(map[string]string, len(m.GetLabel()))
	for _, pair := range m.GetLabel() {
		carried[pair.GetName()] = pair.GetValue()
	}
	return carried
}
