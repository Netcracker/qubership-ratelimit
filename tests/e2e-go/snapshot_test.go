//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"sigs.k8s.io/yaml"

	"github.com/netcracker/qubership-ratelimit/api/contract"
	"github.com/netcracker/qubership-ratelimit/api/v1alpha1"
)

// The snapshot endpoint: what one replica enforces, rendered in full on its
// metrics port. It is read through a port-forward the way an operator on
// call would read it, and asserted against the policy it came from: the
// generation the replica applied, the group resolved into the client list
// the engine tests, and the claim path behind a mapped key. The types below
// are the suite's own reading of the document, since the service's package
// is internal to its half of the tree.
var _ = Describe("the snapshot endpoint", Ordered, Label("snapshot"), func() {
	const (
		domain    = "gateway.public"
		probePath = "/e2e-snapshot"
	)
	clients := []string{"zed", "bob", "alice"}

	type snapshotRow struct {
		Domain         string   `json:"domain"`
		Generation     int64    `json:"generation"`
		UID            string   `json:"uid"`
		RuleSetVersion string   `json:"ruleSetVersion"`
		Blocks         int      `json:"blocks"`
		Rules          int      `json:"rules"`
		EffectiveKeys  []string `json:"effectiveKeys"`
	}
	type snapshotSummary struct {
		Replica string        `json:"replica"`
		Domains []snapshotRow `json:"domains"`
	}
	type predicate struct {
		Key      string   `json:"key"`
		Operator string   `json:"operator"`
		Values   []string `json:"values"`
	}
	type rule struct {
		ID      string      `json:"id"`
		Matches []predicate `json:"matches"`
	}
	type block struct {
		Block string `json:"block"`
		Rules []rule `json:"rules"`
	}
	type keyView struct {
		Key   string `json:"key"`
		Claim string `json:"claim"`
	}
	type domainSnapshot struct {
		Domain         string    `json:"domain"`
		Generation     int64     `json:"generation"`
		RuleSetVersion string    `json:"ruleSetVersion"`
		Keys           []keyView `json:"keys"`
		Blocks         []block   `json:"blocks"`
	}

	BeforeAll(func() {
		p := newPolicy(domain, prefixLimits(probePath, "everyone", nil, 100, 60))
		p.Spec.Mappings = []v1alpha1.ClaimMapping{{Key: "tenant", Claim: "org_id"}}
		p.Spec.Groups = []v1alpha1.ClientGroup{{Name: "partners", Clients: clients}}
		p.Spec.Limits[0].Rules = append(p.Spec.Limits[0].Rules, v1alpha1.Rule{
			Name:     "partners",
			Matches:  []v1alpha1.Predicate{{Key: "client", Operator: v1alpha1.OperatorInGroup, Value: "partners"}},
			Counters: []string{"client"},
			Rates:    []v1alpha1.Rate{{Requests: 10, PeriodSeconds: 60}},
		})
		Expect(apply(p)).To(Succeed())
		waitApplied(domain)
	})
	AfterAll(func() {
		deletePolicies(domain)
	})

	It("summarises the domains with the generation each replica applied", func() {
		p, err := getPolicy(domain)
		Expect(err).NotTo(HaveOccurred())
		pods := servicePods()
		Expect(pods).NotTo(BeEmpty())
		for _, pod := range pods {
			var summary snapshotSummary
			body := debugGet(pod, contract.SnapshotPath)
			Expect(json.Unmarshal(body, &summary)).To(Succeed(), "pod %s: %s", pod.Name, body)
			Expect(summary.Replica).To(Equal(pod.Name), "the summary names the replica it came from")

			var row *snapshotRow
			for i := range summary.Domains {
				if summary.Domains[i].Domain == domain {
					row = &summary.Domains[i]
				}
			}
			Expect(row).NotTo(BeNil(), "pod %s lists no row for %s: %s", pod.Name, domain, body)
			Expect(row.Generation).To(Equal(p.Status.ActiveGeneration),
				"pod %s reports a generation other than the one it applied", pod.Name)
			Expect(row.UID).To(Equal(string(p.UID)))
			Expect(row.Blocks).To(Equal(1))
			Expect(row.Rules).To(Equal(2))
			Expect(row.EffectiveKeys).To(ContainElement("tenant"), "the mapped key is missing from the key set")
			Expect(row.RuleSetVersion).To(HaveLen(12))
		}
	})

	It("renders the domain with the group resolved and the claim behind the key", func() {
		pod := servicePods()[0]
		var doc domainSnapshot
		body := debugGet(pod, contract.SnapshotPath+"/"+domain)
		Expect(json.Unmarshal(body, &doc)).To(Succeed(), "pod %s: %s", pod.Name, body)
		Expect(doc.Domain).To(Equal(domain))
		Expect(doc.Blocks).To(HaveLen(1))

		var partners *rule
		for i := range doc.Blocks[0].Rules {
			if doc.Blocks[0].Rules[i].ID == "probe/partners" {
				partners = &doc.Blocks[0].Rules[i]
			}
		}
		Expect(partners).NotTo(BeNil(), "the rule over the group is missing: %s", body)
		Expect(partners.Matches).To(HaveLen(1))
		Expect(partners.Matches[0].Operator).To(Equal("In"), "the group is resolved into the set the engine tests")
		Expect(partners.Matches[0].Values).To(Equal([]string{"alice", "bob", "zed"}),
			"the client list is rendered in full, sorted")

		var tenant *keyView
		for i := range doc.Keys {
			if doc.Keys[i].Key == "tenant" {
				tenant = &doc.Keys[i]
			}
		}
		Expect(tenant).NotTo(BeNil(), "the mapped key is missing from the extraction plan: %s", body)
		Expect(tenant.Claim).To(Equal("org_id"))
	})

	It("answers the same document as YAML", func() {
		pod := servicePods()[0]
		var asJSON, asYAML domainSnapshot
		Expect(json.Unmarshal(debugGet(pod, contract.SnapshotPath+"/"+domain), &asJSON)).To(Succeed())
		body := debugGet(pod, contract.SnapshotPath+"/"+domain+"?format=yaml")
		Expect(strings.HasPrefix(string(body), "{")).To(BeFalse(), "the YAML rendering came back as JSON: %s", body)
		Expect(yaml.Unmarshal(body, &asYAML)).To(Succeed(), "pod %s: %s", pod.Name, body)
		Expect(asYAML).To(Equal(asJSON), "the two renderings carry different documents")
	})

	It("is not found for a domain no policy claims", func() {
		status, _ := debugRequest(servicePods()[0], contract.SnapshotPath+"/gateway.nowhere")
		Expect(status).To(Equal(http.StatusNotFound))
	})
})
