package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserSlice_partitionsTheUsersAmongTheGenerators(t *testing.T) {
	got := [][]int{userSlice(10, 0, 3), userSlice(10, 1, 3), userSlice(10, 2, 3)}
	assert.Equal(t, [][]int{{1, 4, 7, 10}, {2, 5, 8}, {3, 6, 9}}, got)
}

// readTokens returns the rows of a tokens file as user, hot, and token.
func readTokens(t *testing.T, path string) [][3]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	require.Equal(t, "user,hot,token", lines[0], "the header of %s", path)
	rows := make([][3]string, 0, len(lines)-1)
	for _, line := range lines[1:] {
		f := strings.SplitN(line, ",", 3)
		require.Len(t, f, 3, "row %q", line)
		rows = append(rows, [3]string{f[0], f[1], f[2]})
	}
	return rows
}

// A self-signed token carries the user as sub and lives for -ttl.
func TestTokensCommand_selfSignedTokensCarryTheUserAsSub(t *testing.T) {
	out := filepath.Join(t.TempDir(), "tokens.csv")
	require.NoError(t, tokensCommand([]string{"-source", "self-signed", "-users", "12", "-hot", "2",
		"-generator", "1", "-generators", "5", "-ttl", "2h", "-out", out}, io.Discard))

	rows := readTokens(t, out)
	users := make([]string, 0, len(rows))
	hot := make([]string, 0, len(rows))
	for _, r := range rows {
		users = append(users, r[0])
		hot = append(hot, r[1])
	}
	assert.Equal(t, []string{"svt-user-02", "svt-user-07", "svt-user-12"}, users)
	assert.Equal(t, []string{"1", "0", "0"}, hot)

	parts := strings.Split(rows[1][2], ".")
	require.Len(t, parts, 3, "a compact JWS")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Sub string `json:"sub"`
		Iat int64  `json:"iat"`
		Exp int64  `json:"exp"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	assert.Equal(t, "svt-user-07", claims.Sub)
	assert.Equal(t, int64((2*time.Hour+time.Minute)/time.Second), claims.Exp-claims.Iat,
		"exp - iat: the lifetime plus the minute iat is set back by")
}

// fakeKeycloak serves the token endpoint of the realm loadtest for the
// client loadtest. A password grant with the password secret returns
// access-<user>-<n>; a refresh grant succeeds for a refresh token that does
// not end in -revoked.
type fakeKeycloak struct {
	mu        sync.Mutex
	issued    int
	refreshes int
}

func (f *fakeKeycloak) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/realms/loadtest/protocol/openid-connect/token" || r.ParseForm() != nil ||
		r.PostForm.Get("client_id") != "loadtest" {
		http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var user string
	switch r.PostForm.Get("grant_type") {
	case "password":
		user = r.PostForm.Get("username")
		if r.PostForm.Get("password") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Invalid user credentials"}`)
			return
		}
	case "refresh_token":
		f.refreshes++
		token := r.PostForm.Get("refresh_token")
		if strings.HasSuffix(token, "-revoked") {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = fmt.Fprint(w, `{"error":"invalid_grant","error_description":"Session not active"}`)
			return
		}
		user = strings.TrimPrefix(token, "refresh-")
	}
	f.issued++
	_ = json.NewEncoder(w).Encode(map[string]any{
		"access_token":       fmt.Sprintf("access-%s-%d", user, f.issued),
		"expires_in":         300,
		"refresh_token":      "refresh-" + user,
		"refresh_expires_in": 1800,
	})
}

func writeSecret(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	require.NoError(t, os.WriteFile(path, []byte(value+"\n"), 0o600))
	return path
}

// Without -watch the command logs every user of the slice in once and
// writes their access tokens.
func TestTokensCommand_keycloakTokensComeFromThePasswordGrant(t *testing.T) {
	kc := httptest.NewServer(&fakeKeycloak{})
	defer kc.Close()
	out := filepath.Join(t.TempDir(), "tokens.csv")

	require.NoError(t, tokensCommand([]string{"-source", "keycloak", "-keycloak-url", kc.URL, "-realm", "loadtest",
		"-client-id", "loadtest", "-password-file", writeSecret(t, "secret"),
		"-users", "2", "-prefix", "u", "-concurrency", "1", "-out", out}, io.Discard))

	assert.Equal(t, [][3]string{{"u1", "0", "access-u1-1"}, {"u2", "0", "access-u2-2"}}, readTokens(t, out))
}

func TestTokensCommand_failsWhenAUserCannotLogIn(t *testing.T) {
	kc := httptest.NewServer(&fakeKeycloak{})
	defer kc.Close()

	err := tokensCommand([]string{"-source", "keycloak", "-keycloak-url", kc.URL, "-realm", "loadtest",
		"-client-id", "loadtest", "-password-file", writeSecret(t, "wrong"),
		"-users", "3", "-out", filepath.Join(t.TempDir(), "tokens.csv")}, io.Discard)

	assert.ErrorContains(t, err, "3 of 3 users could not log in")
}

// A token is renewed from its refresh token while that is valid, and from a
// new login once the refresh token expired or Keycloak refused it.
func TestKeycloakLogin_renewPrefersTheRefreshToken(t *testing.T) {
	now := time.Now()
	valid := grant{tokenResponse: tokenResponse{RefreshToken: "refresh-a"}, refreshExpires: now.Add(time.Hour)}
	expired := grant{tokenResponse: tokenResponse{RefreshToken: "refresh-b"}, refreshExpires: now.Add(5 * time.Second)}
	revoked := grant{tokenResponse: tokenResponse{RefreshToken: "refresh-c-revoked"}, refreshExpires: now.Add(time.Hour)}

	tests := []struct {
		name          string
		row           tokenRow
		wantToken     string
		wantRefreshes int
	}{
		{"a valid refresh token", tokenRow{user: "a", grant: valid}, "access-a-1", 1},
		{"a refresh token about to expire", tokenRow{user: "b", grant: expired}, "access-b-1", 0},
		{"a refresh token Keycloak refuses", tokenRow{user: "c", grant: revoked}, "access-c-1", 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := &fakeKeycloak{}
			kc := httptest.NewServer(fake)
			defer kc.Close()
			k := keycloakLogin{endpoint: kc.URL + "/realms/loadtest/protocol/openid-connect/token",
				client: kc.Client(), clientID: "loadtest", password: "secret"}

			row := tt.row
			require.NoError(t, k.renew(&row, now))
			assert.Equal(t, tt.wantToken, row.token)
			assert.Equal(t, tt.wantRefreshes, fake.refreshes, "refresh grants sent")
		})
	}
}

// A round renews the tokens past 70 percent of their lifetime and rewrites
// the file with them: at 211 s, u1's token of 300 s is due and u2's of 600 s
// is not.
func TestRenewal_renewsTheDueTokensAndRewritesTheFile(t *testing.T) {
	fake := &fakeKeycloak{}
	kc := httptest.NewServer(fake)
	defer kc.Close()
	issued := time.Date(2027, 1, 16, 0, 0, 0, 0, time.UTC)
	row := func(user string, lifetime time.Duration) tokenRow {
		return tokenRow{user: user, token: "first-" + user, grant: grant{
			tokenResponse:  tokenResponse{RefreshToken: "refresh-" + user},
			expires:        issued.Add(lifetime),
			refreshExpires: issued.Add(time.Hour),
		}}
	}
	out := filepath.Join(t.TempDir(), "tokens.csv")
	r := &renewal{
		login: keycloakLogin{endpoint: kc.URL + "/realms/loadtest/protocol/openid-connect/token",
			client: kc.Client(), clientID: "loadtest", password: "secret"},
		rows:   []tokenRow{row("u1", 300*time.Second), row("u2", 600*time.Second)},
		issued: []time.Time{issued, issued},
		out:    out, concurrency: 1, stdout: io.Discard,
	}

	require.NoError(t, r.renewDue(issued.Add(211*time.Second)))

	assert.Equal(t, [][3]string{{"u1", "0", "access-u1-1"}, {"u2", "0", "first-u2"}}, readTokens(t, out))
}

func TestRenewAt_isSeventyPercentIntoTheLifetime(t *testing.T) {
	issued := time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC)
	assert.Equal(t, issued.Add(210*time.Second), renewAt(issued, issued.Add(300*time.Second)))
}
