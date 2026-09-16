package controller

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"sync"
	"time"

	discoveryv1 "k8s.io/api/discovery/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/netcracker/qubership-ratelimit/api/applied"
	"github.com/netcracker/qubership-ratelimit/api/contract"
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
// from flickering during a rollout: a pod enters the fraction only once ready,
// which is after its first compilation and so already on the current
// generation, and leaves it once it is terminating or no longer ready,
// whichever the Service reports first.

// probeTimeout bounds one replica's answer. It is short because the endpoint
// serves a value read from memory: a replica that needs longer than this is not
// one that is answering checks either.
const probeTimeout = 2 * time.Second

// FleetView is what the leader saw when it asked the replicas.
type FleetView struct {
	// At is when the fleet was asked. A view answered from a round taken
	// earlier carries that round's time, so a reader knows how fresh the
	// answers are; the reconciler stamps it into the status. Zero means the
	// moment of the observation.
	At time.Time

	// RefreshAt is when the probe stops answering from this round: its
	// completion plus the freshness, or one ProbeInterval after At for a
	// probe that reuses nothing. The reconciler times its next look at the
	// fleet by it, so the look takes a new round rather than the same one
	// again. Zero means one ProbeInterval after At.
	RefreshAt time.Time

	// Total is the number of ready endpoints at the time of the probe.
	Total int32

	// Applied is how many of them enforce the generation asked about.
	Applied int32

	// Behind names the replicas that answered with another generation, sorted,
	// for the condition message. Only the first few are worth printing.
	Behind []string

	// Silent names the replicas that did not answer at all. They are kept apart
	// from Behind because the two ask for different fixes: a replica on an old
	// generation is a propagation question, an unreachable one is a question
	// about the metrics port or a network policy in front of it.
	Silent []string

	// Refusing names the replicas that answered with a refusal: the manifest
	// they were last given is one they do not read, and they keep their
	// snapshot. It is what turns into ReplicaFormatUnsupported.
	Refusing []string
}

// ReplicaProbe reads the enforced generation from every ready endpoint of the
// component's own Service. It is the production FleetProbe. It is safe for
// concurrent use, and concurrent observations share one round of answers.
type ReplicaProbe struct {
	// Reader lists the EndpointSlices of the Service.
	Reader client.Reader

	// Namespace and Service name the Service whose ready endpoints are the
	// fleet.
	Namespace string
	Service   string

	// Port is the metrics port, which is where /debug/applied lives. Zero
	// means "the port the Service publishes under contract.MetricsPortName",
	// read from each EndpointSlice: that is the split's contract, where the
	// operator knows nothing of the service's bind address. A fixed port is
	// the one-binary packaging, whose Service publishes no such name.
	Port int

	// HTTP is the client used for the probe; nil means a default with the
	// probe timeout.
	HTTP *http.Client

	// Freshness is the age below which a later Observe reuses a round of
	// answers instead of asking the fleet again. The reconciles of a
	// namespace share one probe, so a freshness equal to their interval costs
	// the fleet one request per replica per cycle rather than one per domain.
	// Zero reuses nothing.
	Freshness time.Duration

	// Now is the clock the freshness is measured by; nil means time.Now.
	Now func() time.Time

	mu    sync.Mutex
	round *fleetRound
}

// fleetRound is one round of answers: the ready endpoints at the time, what
// each of them enforced, or the error that failed the whole round. A round is
// not modified once taken, so a view reads it without the lock.
type fleetRound struct {
	// taken is when the fleet was asked and completed when the last answer
	// was in. The freshness counts from completed: a round that took long,
	// because replicas were slow to answer, would otherwise expire before
	// the next domain could reuse it, and the cycle would fall back to one
	// round per domain.
	taken     time.Time
	completed time.Time
	endpoints []endpoint

	// answers holds what each endpoint enforces; an endpoint that did not
	// answer is named in silent instead.
	answers map[endpoint]applied.Report
	silent  []string
	err     error
}

// Observe reports which ready endpoints enforce the generation of the domain
// asked about, from a round of answers younger than the freshness and taken
// from the same ready endpoints, or from a new round when fresh is set or no
// such round exists. An error means the fleet could not be observed at all,
// which is the one case where Ready is Unknown rather than false: the leader
// does not know, and reporting a guess would be worse than saying so. A
// round that failed is kept like any other, so a fleet that cannot be
// observed costs one round per freshness, not one per domain.
func (p *ReplicaProbe) Observe(
	ctx context.Context, domain string, want store.Applied, fresh bool,
) (FleetView, error) {
	round := p.currentRound(ctx, fresh)
	if round.err != nil {
		return FleetView{}, round.err
	}
	return round.view(domain, want, p.Freshness), nil
}

// currentRound returns the round an observation is answered from: the one
// taken earlier while it completed less than the freshness ago, was taken
// from the ready endpoints of now, and no fresh one was asked for; a new one
// otherwise. The endpoints are read on every observation, from the cache
// and at no cost to the fleet, because a round is only as good as the fleet
// it was taken from: a pod that joined or left since changes the
// denominator, and the reconciles that change fans out have to see it. The
// lock covers the asking, so concurrent reconciles share one round instead
// of each taking their own.
func (p *ReplicaProbe) currentRound(ctx context.Context, fresh bool) *fleetRound {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := p.now()
	endpoints, err := p.endpoints(ctx)
	if err != nil {
		p.round = &fleetRound{taken: now, completed: now, err: err}
		return p.round
	}
	if !fresh && p.round != nil && now.Sub(p.round.completed) < p.Freshness &&
		slices.Equal(endpoints, p.round.endpoints) {
		return p.round
	}
	p.round = p.takeRound(ctx, now, endpoints)
	return p.round
}

func (p *ReplicaProbe) now() time.Time {
	if p.Now != nil {
		return p.Now()
	}
	return time.Now()
}

// takeRound asks every one of the ready endpoints what it enforces. The
// endpoints are asked concurrently, so a round lasts one probe timeout at
// most rather than one per replica.
func (p *ReplicaProbe) takeRound(ctx context.Context, now time.Time, endpoints []endpoint) *fleetRound {
	round := &fleetRound{taken: now, endpoints: endpoints, answers: map[endpoint]applied.Report{}}

	type answer struct {
		report applied.Report
		err    error
	}
	answers := make([]answer, len(endpoints))
	var asking sync.WaitGroup
	for i, endpoint := range endpoints {
		asking.Go(func() {
			answers[i].report, answers[i].err = p.ask(ctx, endpoint)
		})
	}
	asking.Wait()
	round.completed = p.now()

	var lastErr error
	for i, endpoint := range endpoints {
		if answers[i].err != nil {
			lastErr = answers[i].err
			round.silent = append(round.silent, endpoint.name)
			continue
		}
		round.answers[endpoint] = answers[i].report
	}

	// Nobody answered, so this is a statement about the leader's reach rather
	// than about the fleet. A network policy that admits only Prometheus to the
	// metrics port silences every probe, and calling that a stale replica would
	// report a working domain as Degraded. ProbeFailed says what is true: the
	// leader cannot see.
	if len(endpoints) > 0 && len(round.silent) == len(endpoints) {
		round.err = fmt.Errorf("no replica answered %s: %w", contract.AppliedPath, lastErr)
	}
	sort.Strings(round.silent)
	return round
}

// view counts one domain's replicas from the round's answers: an endpoint
// that reported the generation and object asked about is applied, one that
// reported anything else is behind, and one that did not answer is silent.
func (r *fleetRound) view(domain string, want store.Applied, freshness time.Duration) FleetView {
	refreshAt := r.taken.Add(ProbeInterval)
	if freshness > 0 {
		refreshAt = r.completed.Add(freshness)
	}
	view := FleetView{At: r.taken, RefreshAt: refreshAt, Total: int32(len(r.endpoints)), Silent: r.silent}
	for _, endpoint := range r.endpoints {
		report, answered := r.answers[endpoint]
		if !answered {
			continue
		}
		// A refusing replica is behind on every domain by construction: it
		// kept the snapshot from before the manifest it could not read. It is
		// named separately because the reason is not lag.
		if report.Refusal != nil {
			view.Refusing = append(view.Refusing, endpoint.name)
		}
		if reported, ok := report.Domains[domain]; ok &&
			reported.Generation == want.Generation && reported.UID == want.UID {
			view.Applied++
			continue
		}
		view.Behind = append(view.Behind, endpoint.name)
	}
	sort.Strings(view.Behind)
	sort.Strings(view.Refusing)
	return view
}

// endpoint is one ready pod behind the Service, and the port to ask it on.
type endpoint struct {
	name    string
	address string
	port    int
}

// endpoints lists the ready addresses of the Service. An endpoint with no
// target reference is named by its address, which is all the message needs.
func (p *ReplicaProbe) endpoints(ctx context.Context) ([]endpoint, error) {
	var list discoveryv1.EndpointSliceList
	if err := p.Reader.List(ctx, &list,
		client.InNamespace(p.Namespace),
		client.MatchingLabels{discoveryv1.LabelServiceName: p.Service},
	); err != nil {
		return nil, fmt.Errorf("list the EndpointSlices of service %q: %w", p.Service, err)
	}

	var out []endpoint
	for i := range list.Items {
		port, ok := p.portOf(&list.Items[i])
		if !ok {
			// A slice without the port is one the probe cannot ask, whatever
			// it lists: a Service that publishes no metrics port, or an older
			// one. Its endpoints are skipped rather than counted silent, so
			// that a misnamed port reads as no replica and not as a stale one.
			continue
		}
		for _, e := range list.Items[i].Endpoints {
			if e.Conditions.Ready != nil && !*e.Conditions.Ready {
				continue
			}
			// A terminating pod is out of the fraction even if it is still
			// Ready. The check above covers it on a default Service, where
			// the endpoint controller drops ready and keeps serving true; it
			// does not on a Service with publishNotReadyAddresses, which
			// reports every address ready and would leave a draining pod in
			// the denominator until it died. The two conditions mean
			// different things and only this one answers "is this pod on its
			// way out".
			if e.Conditions.Terminating != nil && *e.Conditions.Terminating {
				continue
			}
			if len(e.Addresses) == 0 {
				continue
			}
			name := e.Addresses[0]
			if e.TargetRef != nil && e.TargetRef.Name != "" {
				name = e.TargetRef.Name
			}
			out = append(out, endpoint{name: name, address: e.Addresses[0], port: port})
		}
	}
	sort.Slice(out, func(a, b int) bool { return out[a].name < out[b].name })
	return out, nil
}

// portOf is the port to ask the endpoints of a slice on: the fixed one when
// configured, otherwise the one the slice publishes under the metrics port
// name. A slice can carry the port under another name or not at all, and
// then it has no port this probe can use.
func (p *ReplicaProbe) portOf(slice *discoveryv1.EndpointSlice) (int, bool) {
	if p.Port != 0 {
		return p.Port, true
	}
	for _, port := range slice.Ports {
		if port.Name != nil && *port.Name == contract.MetricsPortName && port.Port != nil {
			return int(*port.Port), true
		}
	}
	return 0, false
}

// ask reads one replica's report: what it enforces per domain, and whether it
// refused the last manifest.
func (p *ReplicaProbe) ask(ctx context.Context, target endpoint) (applied.Report, error) {
	ctx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	// The metrics port speaks plain HTTP by the chart's contract, the way
	// Prometheus scrapes it; whether the hop between two pods is encrypted is
	// the mesh's decision, not this client's.
	address := target.address
	location := url.URL{
		Scheme: "http",
		Host:   net.JoinHostPort(address, strconv.Itoa(target.port)),
		Path:   contract.AppliedPath,
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, location.String(), nil)
	if err != nil {
		return applied.Report{}, err
	}

	caller := p.HTTP
	if caller == nil {
		caller = &http.Client{Timeout: probeTimeout}
	}
	response, err := caller.Do(request)
	if err != nil {
		return applied.Report{}, err
	}
	defer func() { _ = response.Body.Close() }()

	if response.StatusCode != http.StatusOK {
		return applied.Report{}, fmt.Errorf("replica %s answered %s", address, response.Status)
	}
	// A replica that answers with a body this large is not one this leader
	// understands, and reading it whole would be the leader's problem.
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		return applied.Report{}, err
	}

	var report applied.Report
	if err := json.Unmarshal(body, &report); err != nil {
		return applied.Report{}, fmt.Errorf("decode the reply of replica %s: %w", address, err)
	}
	return report, nil
}

// errNoProbe is what a reconciler reports when it has no way to observe the
// fleet — no Service configured, so nothing to ask.
var errNoProbe = errors.New("no replica probe is configured")
