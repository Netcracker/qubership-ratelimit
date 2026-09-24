package redisconn

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-logr/logr"
	dbaasbase "github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3"
	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model"
	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model/rest"
	"github.com/netcracker/qubership-core-lib-go/v3/configloader"
	"github.com/netcracker/qubership-core-lib-go/v3/security"
	"github.com/netcracker/qubership-core-lib-go/v3/serviceloader"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The properties the DBaaS Redis adapter returns, as dbaas-operator writes
// them into the Secret and the client reads them back: JSON numbers arrive
// as float64.
func adapterProperties(password string) map[string]any {
	return map[string]any{
		"host": "ratelimit-redis.core", "port": float64(6379), "service": "ratelimit-redis",
		"url": "redis://ratelimit-redis.core:6379", "password": password, "role": "admin",
	}
}

// resolver stands in for the DBaaS client and records what it was asked.
type resolver struct {
	mu         sync.Mutex
	properties map[string]any
	err        error
	asked      []map[string]any
}

func (r *resolver) set(properties map[string]any, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.properties, r.err = properties, err
}

func (r *resolver) GetConnection(_ context.Context, dbType string, classifier map[string]any,
	_ rest.BaseDbParams) (map[string]any, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dbType != Type {
		return nil, errors.New("asked for " + dbType)
	}
	r.asked = append(r.asked, classifier)
	return r.properties, r.err
}

func TestParse_theAdapterProperties(t *testing.T) {
	connection, err := Parse(adapterProperties("first"))
	require.NoError(t, err)
	assert.Equal(t, "ratelimit-redis.core:6379", connection.Addr())
	assert.Equal(t, "first", connection.Password)
	assert.Empty(t, connection.Username)
}

// The properties are an untyped map on the aggregator's side: a port can
// arrive as a string, and a host and a port can be missing where the url
// carries them.
func TestParse_acceptsThePortAsTextAndTheAddressFromTheURL(t *testing.T) {
	connection, err := Parse(map[string]any{"host": "h", "port": "6380"})
	require.NoError(t, err)
	assert.Equal(t, "h:6380", connection.Addr())

	connection, err = Parse(map[string]any{"url": "redis://from-url.core:6379"})
	require.NoError(t, err)
	assert.Equal(t, "from-url.core:6379", connection.Addr())
}

// A replica that guessed an address would count apart from its peers, so
// every unreadable connection is an error, never a default.
func TestParse_refusals(t *testing.T) {
	for name, properties := range map[string]map[string]any{
		"no address":        {"password": "p"},
		"port out of range": {"host": "h", "port": float64(70000)},
		"fractional port":   {"host": "h", "port": 6379.5},
		"port not a number": {"host": "h", "port": "six"},
		"tls url":           {"url": "rediss://h:6379"},
		"url without port":  {"url": "redis://h"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(properties)
			assert.Error(t, err)
		})
	}
}

// The service asks for its own database: the classifier the chart's claim
// carries, and the redis type.
func TestOpen_asksForTheServicesOwnDatabase(t *testing.T) {
	r := &resolver{properties: adapterProperties("first")}
	_, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)
	require.Len(t, r.asked, 1)
	assert.Equal(t, map[string]any{
		"microserviceName": "ratelimit-service", "scope": "service", "namespace": "core",
	}, r.asked[0])
}

// A replica whose database cannot be resolved does not start, and the error
// names the classifier it looked for.
func TestOpen_failsWithTheClassifierItLookedFor(t *testing.T) {
	r := &resolver{err: errors.New("403 from dbaas-agent")}
	_, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ratelimit-service")
	assert.Contains(t, err.Error(), "403 from dbaas-agent")
}

// A rotated password is taken up in place: the credentials provider answers
// the new one from the next dial on, and Run keeps going.
func TestSource_followsARotatedPassword(t *testing.T) {
	r := &resolver{properties: adapterProperties("first")}
	source, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)
	source.Resync = 10 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- source.Run(ctx) }()

	r.set(adapterProperties("second"), nil)
	require.Eventually(t, func() bool {
		_, password := source.Credentials()
		return password == "second"
	}, 5*time.Second, 5*time.Millisecond)

	cancel()
	require.NoError(t, <-done)
}

// An address that moves is a different database: Run ends with an error
// that names both, and the process restarts onto the new one.
func TestSource_endsWhenTheAddressMoves(t *testing.T) {
	r := &resolver{properties: adapterProperties("first")}
	source, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)
	source.Resync = 10 * time.Millisecond

	moved := adapterProperties("first")
	moved["host"] = "elsewhere.core"
	r.set(moved, nil)

	done := make(chan error, 1)
	go func() { done <- source.Run(context.Background()) }()
	select {
	case err := <-done:
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ratelimit-redis.core:6379")
		assert.Contains(t, err.Error(), "elsewhere.core:6379")
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not end when the address moved")
	}
}

// A resolution that fails mid-run is logged and the last good connection
// kept.
func TestSource_keepsTheLastGoodConnectionThroughAFailedResolution(t *testing.T) {
	r := &resolver{properties: adapterProperties("first")}
	source, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)

	r.set(nil, errors.New("mid-swap"))
	require.NoError(t, source.reload(context.Background()))
	assert.Equal(t, "ratelimit-redis.core:6379", source.Connection().Addr())
	_, password := source.Credentials()
	assert.Equal(t, "first", password)
}

// The platform's DbaaSPool is a Resolver as it stands: its providers answer
// before any REST call, which is where the mounted Secret is read. A
// provider stands in for the mount, which the client reads from a fixed path.
func TestSource_resolvesThroughThePlatformPool(t *testing.T) {
	t.Setenv("MICROSERVICE_NAMESPACE", "core")
	configloader.InitWithSourcesArray([]*configloader.PropertySource{configloader.EnvPropertySource()})
	serviceloader.Register(2, &security.DummyToken{})

	mount := &provider{properties: adapterProperties("first")}
	pool := dbaasbase.NewDbaaSPool(model.PoolOptions{LogicalDbProviders: []model.LogicalDbProvider{mount}})
	source, err := Open(context.Background(), pool, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)
	assert.Equal(t, "ratelimit-redis.core:6379", source.Connection().Addr())
	assert.Equal(t, Type, mount.dbType)
	assert.Equal(t, "ratelimit-service", mount.classifier["microserviceName"])
}

// provider is a LogicalDbProvider answering one database.
type provider struct {
	properties map[string]any
	dbType     string
	classifier map[string]any
}

func (p *provider) GetOrCreateDb(string, map[string]any, rest.BaseDbParams) (*model.LogicalDb, error) {
	return nil, errors.New("the service never creates its database")
}

func (p *provider) GetConnection(dbType string, classifier map[string]any,
	_ rest.BaseDbParams) (map[string]any, error) {
	p.dbType, p.classifier = dbType, classifier
	return p.properties, nil
}
