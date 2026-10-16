// Loadkit prepares and checks a load test run of the rate limit through a
// gateway. It has three commands:
//
//	loadkit keycloak-users  creates or deletes the test users in a Keycloak realm
//	loadkit tokens          writes a bearer token per test user, from Keycloak
//	                        or self-signed, and with -watch keeps them fresh
//	loadkit verify          reads the JMeter results and checks them against
//	                        the load steps and the rate limit windows
//
// Run a command with -h for its flags. Every command exits with status 2 on a
// usage or I/O error; verify exits with status 1 when a check fails.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// errChecksFailed is returned by a command whose run completed and whose
// checks did not pass; run maps it to exit status 1.
var errChecksFailed = errors.New("checks failed")

func run(args []string, stdout, stderr io.Writer) int {
	commands := map[string]func([]string, io.Writer) error{
		"keycloak-users": keycloakUsersCommand,
		"tokens":         tokensCommand,
		"verify":         verifyCommand,
	}
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, "usage: loadkit keycloak-users|tokens|verify [flags]")
		return 2
	}
	cmd, ok := commands[args[0]]
	if !ok {
		_, _ = fmt.Fprintf(stderr, "loadkit: unknown command %q; want keycloak-users, tokens, or verify\n", args[0])
		return 2
	}
	err := cmd(args[1:], stdout)
	switch {
	case err == nil, errors.Is(err, flag.ErrHelp):
		return 0
	case errors.Is(err, errChecksFailed):
		_, _ = fmt.Fprintf(stderr, "loadkit %s: %v\n", args[0], err)
		return 1
	default:
		_, _ = fmt.Fprintf(stderr, "loadkit %s: %v\n", args[0], err)
		return 2
	}
}
