//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

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
		Expect(hasSeries(families, "ratelimit_checks_total",
			map[string]string{"domain": domain, "verdict": "ok"})).To(BeTrue(),
			"the scrape carries no admitted checks")
		Expect(hasSeries(families, "ratelimit_checks_total",
			map[string]string{"domain": domain, "verdict": "over_limit"})).To(BeTrue(),
			"the scrape carries no refused checks")
	})

	It("attributes the refusal to its block/rule identity", func() {
		Expect(hasSeries(families, "ratelimit_decisions_total",
			map[string]string{"domain": domain, "outcome": "over_limit", "rule": rule})).To(BeTrue(),
			"the scrape does not attribute the refusal to %s", rule)
	})

	It("counts the near-limit precursor", func() {
		Expect(hasSeries(families, "ratelimit_near_limit_total",
			map[string]string{"domain": domain, "rule": rule})).To(BeTrue(),
			"the scrape carries no near-limit precursor for %s", rule)
	})

	It("times checks with the filter-timeout boundary", func() {
		// The 50ms bucket is the boundary the gateway filter timeout sits on;
		// "p99 over the budget" reads exactly only while it exists.
		Expect(histogramBound(families, "ratelimit_check_duration_seconds",
			map[string]string{"domain": domain}, 0.05)).To(BeTrue(),
			"the check duration histogram lost its 0.05 bucket boundary")
	})

	It("counts the configurations applied", func() {
		Expect(hasSeries(families, "ratelimit_snapshot_rebuilds_total",
			map[string]string{"result": "ok"})).To(BeTrue(),
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
		Expect(gaugeValue(operator, "ratelimit_policy_enforced",
			map[string]string{"domain": domain})).To(Equal(1.0))
		Expect(gaugeValue(operator, "ratelimit_policy_replicas",
			map[string]string{"domain": domain, "state": "applied"})).To(BeNumerically(">", 0),
			"the operator's scrape carries no fleet")
		Expect(gaugeValue(operator, "ratelimit_leader", nil)).To(Equal(1.0),
			"the operator holds the lease and its scrape has to say so")
	})

	It("gauges the domain decision buckets", func() {
		Expect(hasSeries(families, "ratelimit_domain_decision_buckets",
			map[string]string{"domain": domain})).To(BeTrue(),
			"the scrape carries no domain budget gauge")
	})

	It("carries the Go runtime series on both scrapes", func() {
		Expect(families).To(HaveKey("go_goroutines"),
			"the Go runtime series are not riding along on the service")
		Expect(operator).To(HaveKey("go_goroutines"),
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
	port := 0
	for _, c := range pod.Spec.Containers {
		for _, p := range c.Ports {
			if p.Name == "metrics" {
				port = int(p.ContainerPort)
			}
		}
	}
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

// hasSeries reports whether the family holds a series carrying every given
// label pair.
func hasSeries(families map[string]*dto.MetricFamily, name string, labels map[string]string) bool {
	return seriesOf(families, name, labels) != nil
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

// histogramBound reports whether the matching histogram series declares a
// bucket with the given upper bound.
func histogramBound(families map[string]*dto.MetricFamily, name string, labels map[string]string, bound float64) bool {
	m := seriesOf(families, name, labels)
	if m == nil {
		return false
	}
	for _, b := range m.GetHistogram().GetBucket() {
		if b.GetUpperBound() == bound {
			return true
		}
	}
	return false
}

func seriesOf(families map[string]*dto.MetricFamily, name string, labels map[string]string) *dto.Metric {
	family := families[name]
	if family == nil {
		return nil
	}
	for _, m := range family.Metric {
		carried := map[string]string{}
		for _, pair := range m.Label {
			carried[pair.GetName()] = pair.GetValue()
		}
		matches := true
		for k, v := range labels {
			if carried[k] != v {
				matches = false
				break
			}
		}
		if matches {
			return m
		}
	}
	return nil
}
