package redisconn

import (
	"context"
	"errors"
	"fmt"
	"reflect"
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

// firstConnection is the connection adapterProperties("first") describes.
func firstConnection() Connection {
	return Connection{
		Host: "ratelimit-redis.core", Port: 6379, URL: "redis://ratelimit-redis.core:6379", Password: "first",
	}
}

// ownDatabase is the classifier of the service's own database in the
// namespace core.
var ownDatabase = map[string]any{"microserviceName": "ratelimit-service", "scope": "service", "namespace": "core"}

// resolver stands in for the DBaaS client: it serves one redis database, the
// one of ownDatabase, and refuses a lookup of any other.
type resolver struct {
	mu         sync.Mutex
	properties map[string]any
	err        error
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
	if dbType != Type || !reflect.DeepEqual(classifier, ownDatabase) {
		return nil, fmt.Errorf("no %s database %v; this resolver serves the %s database %v",
			dbType, classifier, Type, ownDatabase)
	}
	return r.properties, r.err
}

// blockingResolver returns only when its context ends, the way the client's
// REST fallback retries until it is canceled.
type blockingResolver struct{}

func (blockingResolver) GetConnection(ctx context.Context, _ string, _ map[string]any,
	_ rest.BaseDbParams) (map[string]any, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// openOwnDatabase opens a source on a resolver that serves properties.
func openOwnDatabase(t *testing.T, properties map[string]any) (*Source, *resolver) {
	t.Helper()
	r := &resolver{properties: properties}
	source, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())
	require.NoError(t, err)
	return source, r
}

// run starts source.Run and returns the channel its result arrives on, and
// the function that stops it. The test's end stops it too.
func run(t *testing.T, source *Source) (done <-chan error, stop context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	result := make(chan error, 1)
	go func() { result <- source.Run(ctx) }()
	return result, cancel
}

func TestParse_readsTheAdapterProperties(t *testing.T) {
	connection, err := Parse(adapterProperties("first"))

	require.NoError(t, err)
	assert.Equal(t, firstConnection(), connection)
	assert.Equal(t, "ratelimit-redis.core:6379", connection.Addr())
}

// The properties are an untyped map on the aggregator's side, and adapters
// differ: a port can arrive as a string.
func TestParse_acceptsThePortAsText(t *testing.T) {
	connection, err := Parse(map[string]any{"host": "h", "port": "6380"})

	require.NoError(t, err)
	assert.Equal(t, "h:6380", connection.Addr())
}

// A port can arrive as a Go int from properties built in Go rather than
// decoded from JSON, and it is read as a number.
func TestParse_acceptsThePortAsAnInt(t *testing.T) {
	connection, err := Parse(map[string]any{"host": "h", "port": 6380})

	require.NoError(t, err)
	assert.Equal(t, "h:6380", connection.Addr())
}

// A port is in the range 1 to 65535, and both ends of it are read. The
// neighbors outside it, 0 and 65536, are rows of
// TestParse_refusesAnAddressItCannotRead.
func TestParse_acceptsAPortAtEitherEndOfTheRange(t *testing.T) {
	for _, c := range []struct {
		name string
		port float64
		addr string
	}{
		{"the lowest port", 1, "h:1"},
		{"the highest port", 65535, "h:65535"},
	} {
		t.Run(c.name, func(t *testing.T) {
			connection, err := Parse(map[string]any{"host": "h", "port": c.port})

			require.NoError(t, err, "Parse with the port %v", c.port)
			assert.Equal(t, c.addr, connection.Addr())
		})
	}
}

// A database that authenticates a user carries a username beside the
// password, and the connection keeps both.
func TestParse_readsTheUsernameOfADatabaseThatHasOne(t *testing.T) {
	properties := adapterProperties("first")
	properties["username"] = "counter-user"

	connection, err := Parse(properties)

	require.NoError(t, err)
	assert.Equal(t, "counter-user", connection.Username)
}

// A host and a port can be missing where the url carries them.
func TestParse_takesTheAddressFromTheURL(t *testing.T) {
	connection, err := Parse(map[string]any{"url": "redis://from-url.core:6379"})

	require.NoError(t, err)
	assert.Equal(t, "from-url.core:6379", connection.Addr())
}

// A replica that guessed an address would count apart from its peers, so
// every unreadable connection is an error, never a default.
func TestParse_refusesAnAddressItCannotRead(t *testing.T) {
	cases := []struct {
		name       string
		properties map[string]any
	}{
		{"no address", map[string]any{"password": "p"}},
		{"a port out of range", map[string]any{"host": "h", "port": float64(70000)}},
		{"a port one past the range", map[string]any{"host": "h", "port": float64(65536)}},
		// The url names a port, so the refusal comes from the range check alone.
		{"a port of zero beside a url that names a port",
			map[string]any{"host": "h", "port": float64(0), "url": "redis://h:6379"}},
		{"a fractional port", map[string]any{"host": "h", "port": 6379.5}},
		{"a port that is not a number", map[string]any{"host": "h", "port": "six"}},
		{"a TLS url", map[string]any{"url": "rediss://h:6379"}},
		{"a url without a port", map[string]any{"url": "redis://h"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Parse(c.properties)
			assert.Error(t, err, "Parse(%v)", c.properties)
		})
	}
}

// The adapter installed with TLS returns its usual host and port and adds
// "tls": true, and the database listens on TLS alone: the flag is refused
// by name rather than dialed in plain text.
func TestParse_refusesADatabaseThatServesTLS(t *testing.T) {
	cases := []struct {
		name string
		flag any
	}{
		{"a boolean flag", true},
		{"a text flag", "true"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			properties := adapterProperties("first")
			properties["tls"] = c.flag

			_, err := Parse(properties)

			assert.ErrorContains(t, err, "tls: true")
		})
	}
}

// A tls flag set to false is read as no TLS. This is the control of
// TestParse_refusesADatabaseThatServesTLS.
func TestParse_readsADatabaseWhoseTLSFlagIsFalse(t *testing.T) {
	properties := adapterProperties("first")
	properties["tls"] = false

	connection, err := Parse(properties)

	require.NoError(t, err)
	assert.Equal(t, "ratelimit-redis.core:6379", connection.Addr())
}

// Open resolves the service's own database: the classifier the chart's claim
// carries, and the redis type. The resolver serves that database alone.
func TestOpen_resolvesTheServicesOwnDatabase(t *testing.T) {
	source, _ := openOwnDatabase(t, adapterProperties("first"))

	assert.Equal(t, firstConnection(), source.Connection())
}

// A replica whose database cannot be resolved does not start, and the error
// names the classifier it looked for.
func TestOpen_failsWithTheClassifierItLookedFor(t *testing.T) {
	refused := errors.New("403 from dbaas-agent")
	r := &resolver{err: refused}

	_, err := Open(context.Background(), r, Classifier("ratelimit-service", "core"), logr.Discard())

	assert.ErrorIs(t, err, refused)
	assert.ErrorContains(t, err, "ratelimit-service")
}

// A rotated password is taken up in place: the credentials provider returns
// the new one from the next dial on, and Run keeps going until it is stopped.
func TestSource_followsARotatedPassword(t *testing.T) {
	source, r := openOwnDatabase(t, adapterProperties("first"))
	source.Resync = 10 * time.Millisecond
	done, stop := run(t, source)

	r.set(adapterProperties("second"), nil)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		_, password := source.Credentials()
		assert.Equal(c, "second", password, "the password of the credentials provider")
	}, 5*time.Second, 5*time.Millisecond, "waiting for Run to take up the rotated password")
	stop()
	assert.NoError(t, <-done, "Run stopped by its context")
}

// A changed username is taken up in place as a rotated password is: the
// credentials provider returns it from the next dial on.
func TestSource_followsAChangedUsername(t *testing.T) {
	properties := adapterProperties("first")
	properties["username"] = "first-user"
	source, r := openOwnDatabase(t, properties)
	source.Resync = 10 * time.Millisecond
	done, stop := run(t, source)

	changed := adapterProperties("first")
	changed["username"] = "second-user"
	r.set(changed, nil)

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		username, _ := source.Credentials()
		assert.Equal(c, "second-user", username, "the username of the credentials provider")
	}, 5*time.Second, 5*time.Millisecond, "waiting for Run to take up the changed username")
	stop()
	assert.NoError(t, <-done, "Run stopped by its context")
}

// An address that moves is a different database: Run ends with an error that
// names both, and the process restarts onto the new one.
func TestSource_endsWhenTheAddressMoves(t *testing.T) {
	source, r := openOwnDatabase(t, adapterProperties("first"))
	source.Resync = 10 * time.Millisecond
	moved := adapterProperties("first")
	moved["host"] = "elsewhere.core"
	r.set(moved, nil)

	done, _ := run(t, source)

	select {
	case err := <-done:
		assert.ErrorContains(t, err, "ratelimit-redis.core:6379")
		assert.ErrorContains(t, err, "elsewhere.core:6379")
	case <-time.After(5 * time.Second):
		t.Fatal("waited 5s for Run to end on the moved address; it is still running")
	}
}

// A resolution that fails mid-run is logged and the last good connection
// kept. The test calls the resolution Run makes on every tick, since a failed
// one leaves nothing but a log line to wait for.
func TestSource_keepsTheLastGoodConnectionThroughAFailedResolution(t *testing.T) {
	source, r := openOwnDatabase(t, adapterProperties("first"))
	r.set(nil, errors.New("mid-swap"))

	err := source.reload(context.Background())

	require.NoError(t, err)
	assert.Equal(t, firstConnection(), source.Connection())
}

// A lookup that does not answer, such as the client's REST fallback after a
// Secret that does not match, fails within the timeout and names the
// classifier. Open sets no timeout of its own, so the test resolves through
// the source directly with a short one; a second is far above it and far
// below the default.
func TestSource_endsAResolutionThatDoesNotAnswerAtTheTimeout(t *testing.T) {
	source, _ := openOwnDatabase(t, adapterProperties("first"))
	source.Timeout = 20 * time.Millisecond
	source.Resolver = blockingResolver{}
	start := time.Now()

	_, err := source.resolve(context.Background())

	assert.Less(t, time.Since(start), time.Second, "the time the resolution took")
	assert.ErrorContains(t, err, "ratelimit-service")
	assert.ErrorContains(t, err, "no mounted Secret matched it")
}

// Mid-run, a lookup that does not answer leaves the last good connection in
// place.
func TestSource_keepsTheConnectionThroughAResolutionThatDoesNotAnswer(t *testing.T) {
	source, _ := openOwnDatabase(t, adapterProperties("first"))
	source.Timeout = 20 * time.Millisecond
	source.Resolver = blockingResolver{}

	err := source.reload(context.Background())

	require.NoError(t, err)
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
	assert.Equal(t, firstConnection(), source.Connection())
}

// provider is a LogicalDbProvider serving one redis database, the one of
// ownDatabase. A lookup of any other is an error, which the pool returns
// without falling back to REST.
type provider struct {
	properties map[string]any
}

func (p *provider) GetOrCreateDb(string, map[string]any, rest.BaseDbParams) (*model.LogicalDb, error) {
	return nil, errors.New("the service never creates its database")
}

func (p *provider) GetConnection(dbType string, classifier map[string]any,
	_ rest.BaseDbParams) (map[string]any, error) {
	if dbType != Type || !reflect.DeepEqual(classifier, ownDatabase) {
		return nil, fmt.Errorf("no %s database %v; this provider serves the %s database %v",
			dbType, classifier, Type, ownDatabase)
	}
	return p.properties, nil
}
