package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// keycloakConfig addresses one realm of a Keycloak server.
type keycloakConfig struct {
	// baseURL is the server's root, the part before /realms; it includes
	// the /auth context path on a server that still has one.
	baseURL  string
	realm    string
	caFile   string
	insecure bool
}

func (c keycloakConfig) httpClient() (*http.Client, error) {
	// -insecure is an explicit opt-in for a test stand's self-signed certificate.
	tlsConfig := &tls.Config{InsecureSkipVerify: c.insecure} //nolint:gosec // opt-in, -insecure
	if c.caFile != "" {
		pem, err := os.ReadFile(c.caFile)
		if err != nil {
			return nil, err
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("%s holds no PEM certificate", c.caFile)
		}
		tlsConfig.RootCAs = pool
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig
	transport.MaxIdleConnsPerHost = 64
	return &http.Client{Transport: transport, Timeout: 30 * time.Second}, nil
}

func (c keycloakConfig) tokenURL(realm string) string {
	return strings.TrimSuffix(c.baseURL, "/") + "/realms/" + url.PathEscape(realm) + "/protocol/openid-connect/token"
}

func (c keycloakConfig) adminURL(path string) string {
	return strings.TrimSuffix(c.baseURL, "/") + "/admin/realms/" + url.PathEscape(c.realm) + path
}

// tokenResponse is the part of an OAuth 2.0 token response loadkit reads.
type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int64  `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int64  `json:"refresh_expires_in"`
}

// grant is a token together with the moments its tokens stop being usable.
type grant struct {
	tokenResponse
	expires        time.Time
	refreshExpires time.Time
}

// requestToken posts form to the token endpoint and returns the grant, or
// an error carrying Keycloak's error and its description.
func requestToken(client *http.Client, endpoint string, form url.Values) (grant, error) {
	issued := time.Now()
	resp, err := client.PostForm(endpoint, form)
	if err != nil {
		return grant{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return grant{}, err
	}
	if resp.StatusCode != http.StatusOK {
		var kcErr struct {
			Error       string `json:"error"`
			Description string `json:"error_description"`
		}
		_ = json.Unmarshal(body, &kcErr)
		return grant{}, fmt.Errorf("token endpoint returned %d: %s %s", resp.StatusCode, kcErr.Error, kcErr.Description)
	}
	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return grant{}, fmt.Errorf("token endpoint returned 200 with a body that is not a token response: %w", err)
	}
	if tr.AccessToken == "" || tr.ExpiresIn <= 0 {
		return grant{}, errors.New("token endpoint returned 200 without an access token and its lifetime")
	}
	g := grant{tokenResponse: tr, expires: issued.Add(time.Duration(tr.ExpiresIn) * time.Second)}
	if tr.RefreshToken != "" && tr.RefreshExpiresIn > 0 {
		g.refreshExpires = issued.Add(time.Duration(tr.RefreshExpiresIn) * time.Second)
	}
	return g, nil
}

// passwordGrant logs a user in with the resource owner password credentials
// grant, which the client needs Direct access grants enabled for.
func passwordGrant(client *http.Client, endpoint, clientID, clientSecret, username, password string) (grant, error) {
	form := url.Values{
		"grant_type": {"password"},
		"client_id":  {clientID},
		"username":   {username},
		"password":   {password},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return requestToken(client, endpoint, form)
}

// refreshGrant renews g with its refresh token, which keeps the user's
// Keycloak session instead of opening a new one.
func refreshGrant(client *http.Client, endpoint, clientID, clientSecret string, g grant) (grant, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {clientID},
		"refresh_token": {g.RefreshToken},
	}
	if clientSecret != "" {
		form.Set("client_secret", clientSecret)
	}
	return requestToken(client, endpoint, form)
}

// adminSession calls the Keycloak admin REST API as a user of the admin
// realm. It logs in again once 70 percent of the access token's lifetime has
// passed, because the master realm's tokens live one minute by default and
// provisioning thousands of users takes longer.
type adminSession struct {
	cfg      keycloakConfig
	client   *http.Client
	realm    string
	clientID string
	user     string
	password string

	mu      sync.Mutex
	token   string
	renewAt time.Time
}

func (s *adminSession) bearer() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token != "" && time.Now().Before(s.renewAt) {
		return s.token, nil
	}
	g, err := passwordGrant(s.client, s.cfg.tokenURL(s.realm), s.clientID, "", s.user, s.password)
	if err != nil {
		return "", fmt.Errorf("admin login to realm %s: %w", s.realm, err)
	}
	s.token = g.AccessToken
	s.renewAt = time.Now().Add(time.Duration(float64(g.ExpiresIn)*0.7) * time.Second)
	return s.token, nil
}

// do sends one admin API request and returns the status and the body.
func (s *adminSession) do(method, path string, body any) (int, []byte, error) {
	token, err := s.bearer()
	if err != nil {
		return 0, nil, err
	}
	var reader io.Reader
	if body != nil {
		raw, err := json.Marshal(body)
		if err != nil {
			return 0, nil, err
		}
		reader = bytes.NewReader(raw)
	}
	req, err := http.NewRequest(method, s.cfg.adminURL(path), reader)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return resp.StatusCode, raw, err
}

// readSecretFile returns the content of path without its trailing line
// breaks, which a file written by echo or an editor ends with.
func readSecretFile(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(raw), "\r\n"), nil
}

// forEach runs fn for every item on n goroutines and returns how many calls
// failed together with the first error.
func forEach[T any](items []T, n int, fn func(T) error) (int, error) {
	var (
		mu       sync.Mutex
		failures int
		first    error
		wg       sync.WaitGroup
	)
	work := make(chan T)
	for range max(n, 1) {
		wg.Go(func() {
			for item := range work {
				if err := fn(item); err != nil {
					mu.Lock()
					failures++
					if first == nil {
						first = err
					}
					mu.Unlock()
				}
			}
		})
	}
	for _, item := range items {
		work <- item
	}
	close(work)
	wg.Wait()
	return failures, first
}
