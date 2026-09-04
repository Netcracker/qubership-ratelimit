package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strconv"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/internal/store"
)

// The leader is the only replica that writes status, but Ready is a statement
// about all of them: "the rules I wrote are the rules being enforced" is only
// true when every pod receiving traffic says so. The leader therefore asks each
// of them, through the read-only /debug/applied endpoint on the metrics port.
//
// The denominator is the ready endpoints of the Service, not the Deployment's
// replica count: a pod that is not ready receives no traffic, so it neither
// enforces anything nor belongs in the fraction. That is also what keeps Ready
// from flickering during a rollout — a new pod joins only once ready, and it
// becomes ready after its first compilation, already on the current generation.

// probeTimeout bounds one replica's answer. It is short because the endpoint
// serves a value read from memory, and a replica that cannot answer in a second
// is not a replica that is enforcing anything either.
const probeTimeout = 2 * time.Second

// FleetView is what the leader saw when it asked the replicas.
type FleetView struct {
	// Total is the number of ready endpoints at the time of the probe.
	Total int32

	// Applied is how many of them enforce the generation asked about.
	Applied int32

	// Behind names the replicas that reported another generation, sorted, for
	// the condition message. Only the first few are worth printing.
	Behind []string
}

// ReplicaProbe reads the enforced generation from every ready endpoint of the
// component's own Service. It is the production FleetProbe.
type ReplicaProbe struct {
	// Reader lists the EndpointSlices of the Service.
	Reader client.Reader

	// Namespace and Service name the Service whose ready endpoints are the
	// fleet.
	Namespace string
	Service   string

	// Port is the metrics port, which is where /debug/applied lives.
	Port int

	// HTTP is the client used for the probe; nil means a default with the
	// probe timeout.
	HTTP *http.Client
}

// Observe asks every ready endpoint which generation of the domain it
// enforces. An error means the fleet could not be observed at all, which is the
// one case where Ready is Unknown rather than false: the leader does not know,
// and reporting a guess would be worse than saying so.
func (p *ReplicaProbe) Observe(ctx context.Context, domain string, want store.Applied) (FleetView, error) {
	endpoints, err := p.endpoints(ctx)
	if err != nil {
		return FleetView{}, err
	}

	view := FleetView{Total: int32(len(endpoints))}
	for _, endpoint := range endpoints {
		applied, err := p.ask(ctx, endpoint.address)
		if err != nil {
			// One unreachable replica is not an unobservable fleet: it is a
			// replica that is demonstrably not enforcing the new generation.
			view.Behind = append(view.Behind, endpoint.name)
			continue
		}
		if reported, ok := applied[domain]; ok &&
			reported.Generation == want.Generation && reported.UID == want.UID {
			view.Applied++
			continue
		}
		view.Behind = append(view.Behind, endpoint.name)
	}
	sort.Strings(view.Behind)
	return view, nil
}

// endpoint is one ready pod behind the Service.
type endpoint struct {
	name    string
	address string
}

// endpoints lists the ready addresses of the Service. An endpoint with no
// target reference is named by its address, which is all the message needs.
func (p *ReplicaProbe) endpoints(ctx context.Context) ([]endpoint, error) {
	var slices discoveryv1.EndpointSliceList
	if err := p.Reader.List(ctx, &slices,
		client.InNamespace(p.Namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: p.Service},
	); err != nil {
		return nil, fmt.Errorf("list the EndpointSlices of service %q: %w", p.Service, err)
	}

	var out []endpoint
	for i := range slices.Items {
		for _, e := range slices.Items[i].Endpoints {
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue
			}
			if len(e.Addresses) == 0 {
				continue
			}
			name := e.Addresses[0]
			if e.TargetRef != nil && e.TargetRef.Name != "" {
				name = e.TargetRef.Name
			}
			out = append(out, endpoint{name: name, address: e.Addresses[0]})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out, nil
}

// ask reads one replica's enforced generations.
func (p *ReplicaProbe) ask(ctx context.Context, address string) (map[string]store.Applied, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	url := "http://" + net.JoinHostPort(address, strconv.Itoa(p.Port)) + store.AppliedPath
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	caller := p.HTTP
	if caller == nil {
		caller = &http.Client{Timeout: probeTimeout}
	}
	response, err := caller.Do(request)
	if err != nil {
		return nil, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("replica %s answered %s", address, response.Status)
	}
	// A replica that answers with a body this large is not one this leader
	// understands, and reading it whole would be the leader's problem.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return nil, err
	}

	var applied map[string]store.Applied
	if err := json.Unmarshal(body, &applied); err != nil {
		return nil, fmt.Errorf("decode the reply of replica %s: %w", address, err)
	}
	return applied, nil
}

// errNoProbe is what a reconciler reports when it has no way to observe the
// fleet — no Service configured, so nothing to ask.
var errNoProbe = errors.New("no replica probe is configured")
