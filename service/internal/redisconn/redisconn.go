// Package redisconn resolves the counter store's connection through the
// platform's DBaaS client and keeps the password current while the replica
// runs.
//
// The database is the one the service chart declares in DBaaS, and
// dbaas-operator materializes its connection into a Secret the pod mounts
// under /etc/secrets/dbaas-secrets, the platform's path for DBaaS Secrets.
// The client reads that mount before anything else: it matches the Secret's
// metadata.json to the classifier and type asked for, and reads
// connectionProperties.json fresh on every call. Only on a miss does it fall
// back to asking DBaaS over REST, which the service pod, holding no token,
// cannot do; a miss is therefore an error that names the classifier, never a
// database guessed from elsewhere.
//
// A password that changes in the Secret reaches the replica through the same
// mount: the kubelet swaps the projection, and the next resolution here reads
// the new value. DBaaS itself does not rotate it, since the Redis adapter
// manages no users; the path serves a Secret rewritten by other means. Connections the pool opens
// afterwards authenticate with it, and those already open stay
// authenticated. An address that moves is a different database, and the
// replica does not follow it in place: Run returns an error, the process
// ends, and the container restarts onto the new address.
package redisconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-logr/logr"
	"github.com/netcracker/qubership-core-lib-go-dbaas-base-client/v3/model/rest"
)

// Type is the DBaaS database type of the counter store.
const Type = "redis"

// DefaultResync is how often Run resolves the connection again, which is
// how a changed password is picked up; the kubelet's own sync period comes on
// top of it.
const DefaultResync = 30 * time.Second

// DefaultResolveTimeout bounds one resolution. The mounted Secret answers at
// once; what takes longer is the client's fallback to DBaaS's REST API, which
// retries for a minute by default and cannot succeed from a pod that holds no
// token. Without the bound a Secret that does not match keeps the replica
// starting past its liveness probe, and the error naming the classifier never
// reaches the log.
const DefaultResolveTimeout = 5 * time.Second

// Resolver is the part of the platform's DbaaSPool this package uses: the
// connection properties of a database, looked up by classifier.
type Resolver interface {
	GetConnection(ctx context.Context, dbType string, classifier map[string]any,
		params rest.BaseDbParams) (map[string]any, error)
}

// Classifier is the identity of the service's own database: the one the
// chart's InternalDatabase and DatabaseSecretClaim declare, so the Secret the
// claim materializes matches it.
func Classifier(microservice, namespace string) map[string]any {
	return map[string]any{
		"microserviceName": microservice,
		"scope":            "service",
		"namespace":        namespace,
	}
}

// Connection is the part of the connection properties the service uses.
type Connection struct {
	// Host and Port address the database; URL is the same address as a
	// redis:// URL, and serves when the properties carry no host.
	Host string
	Port int
	URL  string

	// Username is empty for a database that authenticates by password
	// alone, as the DBaaS Redis adapter's do.
	Username string
	Password string
}

// Addr is the host:port the client dials.
func (c Connection) Addr() string {
	return net.JoinHostPort(c.Host, strconv.Itoa(c.Port))
}

// Parse reads the connection properties DBaaS returns for a Redis database:
// host, port, password, a redis:// url, and a role. Every failure is an
// error: a replica that started on a guessed address would count somewhere
// else than its peers, or nowhere.
//
// A database that serves TLS is refused: the aggregator marks it with
// "tls": true when the Redis adapter is installed with TLS, and such a
// database listens on TLS alone. Dialed in plain text, every decision would
// fail at the store while the replica stayed Ready.
func Parse(properties map[string]any) (Connection, error) {
	if tls, _ := properties["tls"].(bool); tls || text(properties["tls"]) == "true" {
		return Connection{}, errors.New("the database serves TLS only (tls: true), " +
			"and the counter store connects in plain text; " +
			"install the DBaaS Redis adapter without TLS")
	}
	connection := Connection{
		Host:     text(properties["host"]),
		URL:      text(properties["url"]),
		Username: text(properties["username"]),
		Password: text(properties["password"]),
	}
	if raw, ok := properties["port"]; ok && raw != nil {
		port, err := parsePort(raw)
		if err != nil {
			return Connection{}, err
		}
		connection.Port = port
	}
	if connection.Host == "" || connection.Port == 0 {
		if err := fillFromURL(&connection); err != nil {
			return Connection{}, err
		}
	}
	return connection, nil
}

func text(value any) string {
	s, _ := value.(string)
	return s
}

// parsePort accepts the port as a number or as a string: the properties are
// an untyped map on the aggregator's side, and adapters differ.
func parsePort(raw any) (int, error) {
	switch port := raw.(type) {
	case float64:
		if port != float64(int(port)) {
			return 0, fmt.Errorf("port %v is not a whole number", port)
		}
		return checkPort(int(port))
	case int:
		return checkPort(port)
	case string:
		number, err := strconv.Atoi(port)
		if err != nil {
			return 0, fmt.Errorf("port %q is not a number", port)
		}
		return checkPort(number)
	}
	return 0, fmt.Errorf("port %v is neither a number nor a string", raw)
}

func checkPort(port int) (int, error) {
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("port %d is out of range", port)
	}
	return port, nil
}

// fillFromURL takes the host and the port the properties left out from the
// redis:// URL.
func fillFromURL(connection *Connection) error {
	if connection.URL == "" {
		return errors.New("the connection properties carry neither a host and a port nor a url")
	}
	parsed, err := url.Parse(connection.URL)
	if err != nil {
		return fmt.Errorf("url: %w", err)
	}
	if parsed.Scheme != "redis" {
		return fmt.Errorf("url scheme %q is not redis", parsed.Scheme)
	}
	if connection.Host == "" {
		connection.Host = parsed.Hostname()
	}
	if connection.Port == 0 && parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return fmt.Errorf("url port %q is not a number", parsed.Port())
		}
		if connection.Port, err = checkPort(port); err != nil {
			return err
		}
	}
	if connection.Host == "" || connection.Port == 0 {
		return fmt.Errorf("url %q names no host and port", connection.URL)
	}
	return nil
}

// Source is the connection a replica runs on, kept current by Run.
type Source struct {
	Resolver   Resolver
	Classifier map[string]any

	// Resync is how often Run resolves the connection again; zero is
	// DefaultResync.
	Resync time.Duration

	// Timeout bounds one resolution; zero is DefaultResolveTimeout.
	Timeout time.Duration

	Log logr.Logger

	current atomic.Pointer[Connection]
}

// Open resolves the connection a replica starts on.
func Open(ctx context.Context, resolver Resolver, classifier map[string]any, log logr.Logger) (*Source, error) {
	source := &Source{Resolver: resolver, Classifier: classifier, Log: log}
	connection, err := source.resolve(ctx)
	if err != nil {
		return nil, err
	}
	source.current.Store(&connection)
	return source, nil
}

// resolve asks the DBaaS client for the connection once, within Timeout.
func (s *Source) resolve(ctx context.Context) (Connection, error) {
	timeout := s.Timeout
	if timeout <= 0 {
		timeout = DefaultResolveTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	properties, err := s.Resolver.GetConnection(ctx, Type, s.Classifier, rest.BaseDbParams{})
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return Connection{}, fmt.Errorf("resolve the counter store's %s database %v through DBaaS: "+
			"no mounted Secret matched it within %s; check the Secret of the release's DatabaseSecretClaim",
			Type, s.Classifier, timeout)
	}
	if err != nil {
		return Connection{}, fmt.Errorf("resolve the counter store's %s database %v through DBaaS: %w",
			Type, s.Classifier, err)
	}
	connection, err := Parse(properties)
	if err != nil {
		return Connection{}, fmt.Errorf("the counter store's connection properties for %v: %w", s.Classifier, err)
	}
	return connection, nil
}

// Connection is the current connection.
func (s *Source) Connection() Connection { return *s.current.Load() }

// Credentials is the client's credentials provider: it is asked on every new
// connection, so a changed password is used from the next dial on.
func (s *Source) Credentials() (username, password string) {
	current := s.current.Load()
	return current.Username, current.Password
}

// Run resolves the connection every Resync until ctx ends. A new password or
// username is taken up in place; a new address ends Run with an error, which
// ends the process, so the container restarts onto the database the Secret
// now names. A resolution that fails is logged and the last good connection
// kept: the kubelet writes the projection whole, so a failed reading is a
// moment of a swap, or an edit the next one repairs.
func (s *Source) Run(ctx context.Context) error {
	resync := s.Resync
	if resync <= 0 {
		resync = DefaultResync
	}
	ticker := time.NewTicker(resync)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
		if err := s.reload(ctx); err != nil {
			return err
		}
	}
}

// reload resolves once and applies what changed.
func (s *Source) reload(ctx context.Context) error {
	next, err := s.resolve(ctx)
	if err != nil {
		s.Log.Info("the counter store's connection could not be resolved, keeping the current one",
			"error", err.Error())
		return nil
	}
	current := s.current.Load()
	if next.Addr() != current.Addr() {
		return fmt.Errorf("the counter store moved from %s to %s; restarting to connect to it",
			current.Addr(), next.Addr())
	}
	if next.Username != current.Username || next.Password != current.Password {
		s.current.Store(&next)
		s.Log.Info("the counter store's credentials changed; new connections use them", "addr", next.Addr())
	}
	return nil
}
