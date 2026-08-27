//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// The series asserted here are the contract the dashboard and the alerts are
// built on: a renamed metric or label would ship a dashboard full of empty
// panels, and this suite is where that breaks first. Traffic may land on any
// replica, so every assertion runs against the union of all scrapes.
var _ = Describe("the metrics endpoint", Ordered, Label("metrics"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-ratelimit"
		limit     = 2
	)
	var (
		policyName string
		rule       string
		window     time.Time
		families   map[string]*dto.MetricFamily
	)

	BeforeAll(func() {
		// The fixture half runs once even across flake retries: the budget is
		// an hour long, so a retry that minted a fresh policy would find the
		// gateway un-warmable (every probe already refused) and a rule label
		// with no admissions behind it. Only the scrape is retried.
		if policyName == "" {
			policyName = fmt.Sprintf("e2e-metrics-%d", time.Now().Unix())
			rule = policyName + "/probe/per-path"

			// Warmed before the policy exists: warm-up probes would come out
			// of the hour-long budget the burst below is about to spend.
			waitGatewayServes("public-gateway", probePath)
			since := time.Now()
			Expect(apply(newPolicy(policyName, domain,
				prefixLimits(probePath, "per-path", []string{"path"}, limit, "1h")))).To(Succeed())
			waitStoreRebuilt(since)

			window = time.Now()
			codes := gatewayBurst("public-gateway", probePath, limit+2, nil)
			Expect(codes).To(ContainElement(429), "the burst never hit the limit; codes: %v", codes)
		}

		families = scrapeAllReplicas()
	})
	AfterAll(func() {
		if policyName != "" {
			deletePolicies(policyName)
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

	It("attributes the refusal to its policy/block/rule triple", func() {
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

	It("counts snapshot rebuilds", func() {
		Expect(hasSeries(families, "ratelimit_snapshot_rebuilds_total",
			map[string]string{"result": "ok"})).To(BeTrue(),
			"the scrape carries no successful snapshot rebuilds")
	})

	It("reports the policy ready", func() {
		Expect(gaugeValue(families, "ratelimit_policy_ready",
			map[string]string{"policy": namespace + "/" + policyName, "reason": ""})).To(Equal(1.0),
			"the scrape does not report %s/%s ready", namespace, policyName)
	})

	It("gauges the domain decision buckets", func() {
		Expect(hasSeries(families, "ratelimit_domain_decision_buckets",
			map[string]string{"domain": domain})).To(BeTrue(),
			"the scrape carries no domain budget gauge")
	})

	It("carries the Go runtime series", func() {
		Expect(families).To(HaveKey("go_goroutines"),
			"the Go runtime series are not riding along")
	})

	It("leaves the sampled refusal in the log", func() {
		Eventually(operatorLogsSince(window)).WithTimeout(30*time.Second).
			Should(ContainSubstring("rate limit refused domain="+domain),
				"no replica logged the sampled refusal line")
	})
})

// scrapeAllReplicas fetches /metrics from every running replica and merges
// the parses; a series is asserted against the union because the burst may
// have landed on any replica.
func scrapeAllReplicas() map[string]*dto.MetricFamily {
	pods := operatorPods()
	Expect(pods).NotTo(BeEmpty(), "no running replica to scrape")
	merged := map[string]*dto.MetricFamily{}
	httpClient := &http.Client{Timeout: 10 * time.Second}
	for _, pod := range pods {
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
		resp, err := httpClient.Get("http://" + addr + "/metrics")
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
			if have, ok := merged[name]; ok {
				have.Metric = append(have.Metric, family.Metric...)
			} else {
				merged[name] = family
			}
		}
	}
	return merged
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
