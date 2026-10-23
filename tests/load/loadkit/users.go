package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

// keycloakUsersCommand creates the test users <prefix>1 to <prefix>N in a
// realm, or deletes them with -delete. Creating is idempotent: an existing
// user gets its password reset to the given one, so a rerun repairs a
// partial run. Every user gets a name, an email, and a verified email,
// because Keycloak refuses the password grant to an account whose profile is
// incomplete ("Account is not fully set up").
func keycloakUsersCommand(args []string, stdout io.Writer) error {
	fs := flag.NewFlagSet("keycloak-users", flag.ContinueOnError)
	var kc keycloakConfig
	fs.StringVar(&kc.baseURL, "keycloak-url", "", "server root, the part of the URL before /realms")
	fs.StringVar(&kc.realm, "realm", "", "realm of the test users")
	fs.StringVar(&kc.caFile, "ca-file", "",
		"PEM file with the CA certificates to trust instead of the system ones")
	fs.BoolVar(&kc.insecure, "insecure", false, "skip the server certificate check")
	adminRealm := fs.String("admin-realm", "master", "realm the admin user logs in to")
	adminClient := fs.String("admin-client-id", "admin-cli", "client the admin user logs in through")
	adminUser := fs.String("admin-user", "", "user with the manage-users role of the realm")
	adminPasswordFile := fs.String("admin-password-file", "", "file with the admin user's password")
	users := fs.Int("users", 2000, "number of test users")
	prefix := fs.String("prefix", "svt-user-", "prefix of the user names")
	passwordFile := fs.String("password-file", "", "file with the password to give every test user")
	concurrency := fs.Int("concurrency", 8, "admin requests in flight")
	del := fs.Bool("delete", false, "delete the test users instead of creating them")
	if err := fs.Parse(args); err != nil {
		return err
	}
	switch {
	case fs.NArg() > 0:
		return fmt.Errorf("unexpected argument %q", fs.Arg(0))
	case kc.baseURL == "" || kc.realm == "" || *adminUser == "" || *adminPasswordFile == "":
		return errors.New("-keycloak-url, -realm, -admin-user, and -admin-password-file are required")
	case !*del && *passwordFile == "":
		return errors.New("-password-file is required to create users")
	case *users < 1:
		return fmt.Errorf("-users is %d; want at least 1", *users)
	}
	adminPassword, err := readSecretFile(*adminPasswordFile)
	if err != nil {
		return err
	}
	var password string
	if !*del {
		if password, err = readSecretFile(*passwordFile); err != nil {
			return err
		}
	}
	client, err := kc.httpClient()
	if err != nil {
		return err
	}
	admin := &adminSession{cfg: kc, client: client, realm: *adminRealm, clientID: *adminClient,
		user: *adminUser, password: adminPassword}
	if _, err := admin.bearer(); err != nil {
		return err
	}

	names := make([]string, *users)
	for i := range names {
		names[i] = userName(*prefix, i+1, *users)
	}
	op, verb := createUser, "created or updated"
	if *del {
		op, verb = deleteUser, "deleted"
	}
	failures, first := forEach(names, *concurrency, func(name string) error { return op(admin, name, password) })
	if failures > 0 {
		return fmt.Errorf("%d of %d users failed; first error: %w", failures, len(names), first)
	}
	_, _ = fmt.Fprintf(stdout, "%s %d users in realm %s\n", verb, len(names), kc.realm)
	return nil
}

func createUser(admin *adminSession, name, password string) error {
	status, body, err := admin.do(http.MethodPost, "/users", map[string]any{
		"username":      name,
		"enabled":       true,
		"firstName":     "Load",
		"lastName":      "Test",
		"email":         name + "@example.com",
		"emailVerified": true,
		"credentials":   []map[string]any{{"type": "password", "value": password, "temporary": false}},
	})
	if err != nil {
		return fmt.Errorf("user %s: %w", name, err)
	}
	switch status {
	case http.StatusCreated:
		return nil
	case http.StatusConflict:
		id, err := findUser(admin, name)
		if err != nil {
			return err
		}
		status, body, err = admin.do(http.MethodPut, "/users/"+url.PathEscape(id)+"/reset-password",
			map[string]any{"type": "password", "value": password, "temporary": false})
		if err != nil {
			return fmt.Errorf("user %s: %w", name, err)
		}
		if status != http.StatusNoContent {
			return fmt.Errorf("user %s: resetting the password returned %d: %s", name, status, body)
		}
		return nil
	default:
		return fmt.Errorf("user %s: creating returned %d: %s", name, status, body)
	}
}

func deleteUser(admin *adminSession, name, _ string) error {
	id, err := findUser(admin, name)
	if errors.Is(err, errNoUser) {
		return nil
	}
	if err != nil {
		return err
	}
	status, body, err := admin.do(http.MethodDelete, "/users/"+url.PathEscape(id), nil)
	if err != nil {
		return fmt.Errorf("user %s: %w", name, err)
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("user %s: deleting returned %d: %s", name, status, body)
	}
	return nil
}

var errNoUser = errors.New("no such user")

// findUser returns the id of the user with exactly the given name.
func findUser(admin *adminSession, name string) (string, error) {
	status, body, err := admin.do(http.MethodGet, "/users?exact=true&username="+url.QueryEscape(name), nil)
	if err != nil {
		return "", fmt.Errorf("user %s: %w", name, err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("user %s: searching returned %d: %s", name, status, body)
	}
	var found []struct {
		ID       string `json:"id"`
		Username string `json:"username"`
	}
	if err := json.Unmarshal(body, &found); err != nil {
		return "", fmt.Errorf("user %s: the search answer is not a user list: %w", name, err)
	}
	for _, u := range found {
		if u.Username == name {
			return u.ID, nil
		}
	}
	return "", fmt.Errorf("user %s: %w", name, errNoUser)
}
