package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeAdminAPI is the admin REST API of the realm loadtest. The user
// <existing> exists with the id id-<existing>; every other user does not
// until created. It records what each call changed.
type fakeAdminAPI struct {
	existing string

	mu      sync.Mutex
	created map[string]map[string]any
	reset   map[string]string
	deleted []string
}

func (f *fakeAdminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/realms/master/protocol/openid-connect/token" {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "admin", "expires_in": 60})
		return
	}
	if r.Header.Get("Authorization") != "Bearer admin" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	path := strings.TrimPrefix(r.URL.Path, "/admin/realms/loadtest")
	switch {
	case r.Method == http.MethodPost && path == "/users":
		f.create(w, r)
	case r.Method == http.MethodGet && path == "/users":
		f.search(w, r)
	case r.Method == http.MethodPut && strings.HasSuffix(path, "/reset-password"):
		f.resetPassword(w, r, strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/reset-password"))
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/users/"):
		f.deleted = append(f.deleted, strings.TrimPrefix(path, "/users/"))
		w.WriteHeader(http.StatusNoContent)
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func (f *fakeAdminAPI) create(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if body["username"] == f.existing {
		w.WriteHeader(http.StatusConflict)
		return
	}
	f.created[body["username"].(string)] = body
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeAdminAPI) search(w http.ResponseWriter, r *http.Request) {
	found := []map[string]string{}
	if name := r.URL.Query().Get("username"); name == f.existing && r.URL.Query().Get("exact") == "true" {
		found = append(found, map[string]string{"id": "id-" + name, "username": name})
	}
	_ = json.NewEncoder(w).Encode(found)
}

func (f *fakeAdminAPI) resetPassword(w http.ResponseWriter, r *http.Request, id string) {
	var body map[string]any
	if json.NewDecoder(r.Body).Decode(&body) != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	f.reset[id] = fmt.Sprint(body["value"])
	w.WriteHeader(http.StatusNoContent)
}

func usersArgs(t *testing.T, url string, extra ...string) []string {
	return append([]string{"-keycloak-url", url, "-realm", "loadtest", "-admin-user", "admin",
		"-admin-password-file", writeSecret(t, "admin"), "-users", "2", "-prefix", "u"}, extra...)
}

// A new user is created with the password and a complete profile, which
// the password grant requires; an existing one gets the password reset.
func TestKeycloakUsersCommand_createsNewUsersAndResetsExistingOnes(t *testing.T) {
	fake := &fakeAdminAPI{existing: "u2", created: map[string]map[string]any{}, reset: map[string]string{}}
	kc := httptest.NewServer(fake)
	defer kc.Close()

	require.NoError(t, keycloakUsersCommand(usersArgs(t, kc.URL, "-password-file", writeSecret(t, "secret")), io.Discard))

	require.Contains(t, fake.created, "u1")
	assert.Equal(t, map[string]any{
		"username": "u1", "enabled": true, "firstName": "Load", "lastName": "Test",
		"email": "u1@example.com", "emailVerified": true,
		"credentials": []any{map[string]any{"type": "password", "value": "secret", "temporary": false}},
	}, fake.created["u1"])
	assert.Equal(t, map[string]string{"id-u2": "secret"}, fake.reset)
}

// Deleting skips a user that does not exist and removes one that does.
func TestKeycloakUsersCommand_deleteRemovesTheUsersThatExist(t *testing.T) {
	fake := &fakeAdminAPI{existing: "u2", created: map[string]map[string]any{}, reset: map[string]string{}}
	kc := httptest.NewServer(fake)
	defer kc.Close()

	require.NoError(t, keycloakUsersCommand(usersArgs(t, kc.URL, "-delete"), io.Discard))

	sort.Strings(fake.deleted)
	assert.Equal(t, []string{"id-u2"}, fake.deleted)
}
