package m2m

import (
	"context"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	qubetoken "github.com/netcracker/qubership-core-lib-go/v3/security/token"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A token is refused by its time claims with the leeway of 30 seconds the
// platform's verifier allows: one issued in the future, one without an issue
// time, and one that is not valid until past the leeway. Each comes back with
// the error the management API maps onto its 401 detail.
func TestNewVerifier_refusesATokenOnItsTimeClaims(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)

	for _, tc := range []struct {
		name     string
		override jwt.MapClaims
		want     error
	}{
		{"issued an hour ahead", jwt.MapClaims{"iat": time.Now().Add(time.Hour).Unix()},
			jwt.ErrTokenUsedBeforeIssued},
		{"no issue time", jwt.MapClaims{"iat": nil}, qubetoken.ErrTokenClaimMissing},
		{"not valid until 35 seconds ahead, past the leeway",
			jwt.MapClaims{"nbf": time.Now().Add(35 * time.Second).Unix()}, jwt.ErrTokenNotValidYet},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifier.Verify(ctx, c.token(t, c.key, "cluster", tc.override))
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

// A token that is not valid until 25 seconds ahead is inside the leeway, and
// accepted. TestNewVerifier_refusesATokenOnItsTimeClaims holds the one
// past it.
func TestNewVerifier_acceptsATokenNotValidYetInsideTheLeeway(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)

	_, err = verifier.Verify(ctx, c.token(t, c.key, "cluster", jwt.MapClaims{
		"nbf": time.Now().Add(25 * time.Second).Unix(),
	}))

	assert.NoError(t, err, "Verify of a token not valid until 25 seconds ahead")
}

// A token whose header names none is refused by its algorithm, before a key is
// looked up, although it carries the claims of an accepted token under the
// cluster's key id.
func TestNewVerifier_refusesATokenSignedWithNone(t *testing.T) {
	c := newCluster(t)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	verifier, err := NewVerifier(ctx, Config{Audience: audience, Token: c.podToken})
	require.NoError(t, err)
	// The payload of an accepted token, under a header that names none, and
	// without the signature.
	_, signed, _ := strings.Cut(c.token(t, c.key, "cluster", nil), ".")
	payload, _, _ := strings.Cut(signed, ".")
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"cluster","typ":"JWT"}`)) +
		"." + payload + "."

	_, err = verifier.Verify(ctx, unsigned)

	assert.ErrorIs(t, err, jwt.ErrTokenSignatureInvalid)
}
