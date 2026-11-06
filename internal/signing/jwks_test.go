package signing_test

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/server"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// secret stands in for PULSAR_SECRET.
var secret = [32]byte{1, 2, 3}

// ready returns a channel that is already closed.
func ready() <-chan struct{} {
	ch := make(chan struct{})
	close(ch)
	return ch
}

// newHandler returns pulsar's handler for the OP at https://op.example,
// signing with keys.
func newHandler(t *testing.T, pool *pgxpool.Pool, keys *signing.KeySet) http.Handler {
	t.Helper()
	issuer, err := oidc.ParseIssuer("https://op.example")
	if err != nil {
		t.Fatal(err)
	}
	return server.New(issuer, pool, keys, ready())
}

// load returns a key set for pool, loaded.
func load(t *testing.T, pool *pgxpool.Pool) *signing.KeySet {
	t.Helper()
	keys := signing.New(pool, secret)
	if err := keys.Load(t.Context()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return keys
}

// getJWKS sends GET /jwks to handler and returns the response.
func getJWKS(t *testing.T, handler http.Handler) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/jwks", http.NoBody)
	handler.ServeHTTP(rec, req)
	return rec
}

// jwkSet is a JWK Set with every member of each key kept, so that a test
// sees any member the handler should not have published.
type jwkSet struct {
	Keys []map[string]string `json:"keys"`
}

// decodeJWKS decodes a 200 response to GET /jwks.
func decodeJWKS(t *testing.T, rec *httptest.ResponseRecorder) jwkSet {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /jwks status = %d, want %d", rec.Code, http.StatusOK)
	}
	var set jwkSet
	if err := json.Unmarshal(rec.Body.Bytes(), &set); err != nil {
		t.Fatalf("GET /jwks body is not a JWK Set of string members: %v", err)
	}
	return set
}

// kids returns the kid of each key in set, in order.
func kids(set jwkSet) []string {
	var kids []string
	for _, key := range set.Keys {
		kids = append(kids, key["kid"])
	}
	return kids
}

// REQ-JWK-1, REQ-JWK-3, REQ-JWK-4, REQ-JWA-1, REQ-JWA-3, REQ-JWA-4,
// REQ-JWA-5: the JWK Set holds the RSA public key, of 2048 bits, with
// "kty", "n" and "e" in their minimal form, its "use", "alg" and a "kid"
// that is its RFC 7638 thumbprint, and no private member.
func TestJWKS(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	rec := getJWKS(t, newHandler(t, pool, load(t, pool)))

	wantHeader := map[string]string{
		"Content-Type":                "application/json",
		"Cache-Control":               "public, max-age=60",
		"Access-Control-Allow-Origin": "*",
	}
	gotHeader := make(map[string]string, len(wantHeader))
	for k := range wantHeader {
		gotHeader[k] = rec.Header().Get(k)
	}
	if diff := cmp.Diff(wantHeader, gotHeader); diff != "" {
		t.Errorf("GET /jwks headers mismatch (-want +got):\n%s", diff)
	}

	set := decodeJWKS(t, rec)
	if len(set.Keys) != 1 {
		t.Fatalf("GET /jwks has %d keys, want 1", len(set.Keys))
	}
	key := set.Keys[0]
	if diff := cmp.Diff([]string{"alg", "e", "kid", "kty", "n", "use"}, slices.Sorted(maps.Keys(key))); diff != "" {
		t.Errorf("GET /jwks key members mismatch (-want +got):\n%s", diff)
	}
	want := map[string]string{"kty": "RSA", "use": "sig", "alg": "RS256", "e": "AQAB"}
	got := map[string]string{"kty": key["kty"], "use": key["use"], "alg": key["alg"], "e": key["e"]}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("GET /jwks key mismatch (-want +got):\n%s", diff)
	}

	n, err := base64.RawURLEncoding.Strict().DecodeString(key["n"])
	if err != nil {
		t.Fatalf("GET /jwks key n is not base64url without padding: %v", err)
	}
	// 256 octets with a nonzero first one: a 2048-bit modulus in the
	// minimum number of octets.
	if len(n) != 256 || n[0] == 0 || n[0]&0x80 == 0 {
		t.Errorf("GET /jwks key n is %d octets, the first %#x; want 256, the first with its high bit set", len(n), n[0])
	}

	// RFC 7638 §3.2: the required members, in lexicographic order, with no
	// whitespace.
	thumbprint := sha256.Sum256([]byte(`{"e":"` + key["e"] + `","kty":"RSA","n":"` + key["n"] + `"}`))
	if want := base64.RawURLEncoding.EncodeToString(thumbprint[:]); key["kid"] != want {
		t.Errorf("GET /jwks key kid = %q, want its JWK Thumbprint %q", key["kid"], want)
	}
}

// Before the key set is loaded, as while pulsar migrates, the JWK Set is
// not served, and the refusal is not cached.
func TestJWKSBeforeLoad(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.UnreachableURL(t))
	rec := getJWKS(t, newHandler(t, pool, signing.New(pool, secret)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /jwks before Load status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Errorf("GET /jwks before Load Cache-Control = %q, want %q", got, want)
	}
}

// REQ-JWA-2: a JWS signed through the active key's crypto.Signer, as
// RS256 defines, verifies against the published JWK Set.
func TestSignatureVerifiesAgainstJWKS(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	keys := load(t, pool)
	active, err := keys.Active()
	if err != nil {
		t.Fatalf("Active() error = %v", err)
	}

	const payload = `{"iss":"https://op.example"}`
	header, err := json.Marshal(map[string]string{"alg": "RS256", "kid": active.KID})
	if err != nil {
		t.Fatal(err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload))
	digest := sha256.Sum256([]byte(signingInput))
	sig, err := active.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}
	compact := signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)

	var set jose.JSONWebKeySet
	if err := json.Unmarshal(getJWKS(t, newHandler(t, pool, keys)).Body.Bytes(), &set); err != nil {
		t.Fatalf("GET /jwks body: %v", err)
	}
	jws, err := jose.ParseSignedCompact(compact, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		t.Fatalf("ParseSignedCompact() error = %v", err)
	}
	published := set.Key(jws.Signatures[0].Header.KeyID)
	if len(published) != 1 {
		t.Fatalf("GET /jwks has %d keys with kid %q, want 1", len(published), active.KID)
	}
	got, err := jws.Verify(published[0])
	if err != nil {
		t.Fatalf("Verify() against the published key error = %v", err)
	}
	if string(got) != payload {
		t.Errorf("Verify() = %q, want %q", got, payload)
	}
}

// REQ-JWK-2: a key that another replica stores appears in this replica's
// JWK Set after one reload interval, not before, under a kid of its own.
//
// The pool is opened inside the bubble, so that its connections and
// timers belong to it, on an address rather than a host name, so that it
// never touches net's resolver (see postgrestest.ResolveHost). Requests go
// to the handler directly: a server's listener, blocked in the network,
// would keep the bubble's clock from advancing.
func TestJWKSReloadsKeyFromAnotherReplica(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		ctx, cancel := context.WithCancel(t.Context())
		pool, err := pgxpool.New(ctx, databaseURL)
		if err != nil {
			t.Fatal(err)
		}
		defer pool.Close()
		replica, other := load(t, pool), load(t, pool)
		handler := newHandler(t, pool, replica)
		before := kids(decodeJWKS(t, getJWKS(t, handler)))

		reloading := make(chan struct{})
		go func() {
			defer close(reloading)
			replica.Run(ctx, slog.New(slog.NewTextHandler(t.Output(), nil)))
		}()
		defer func() {
			cancel()
			<-reloading
		}()
		added, err := signing.AddKey(ctx, other)
		if err != nil {
			t.Fatalf("AddKey() error = %v", err)
		}

		time.Sleep(signing.ReloadInterval - time.Nanosecond)
		synctest.Wait()
		if got := kids(decodeJWKS(t, getJWKS(t, handler))); !cmp.Equal(got, before) {
			t.Errorf("GET /jwks just before one reload interval has kids %q, want %q", got, before)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		// The keys are dated the same instant of the bubble's clock, so
		// their order is not the order they were added in.
		got := slices.Sorted(slices.Values(kids(decodeJWKS(t, getJWKS(t, handler)))))
		if want := slices.Sorted(slices.Values(append(slices.Clone(before), added))); !cmp.Equal(got, want) {
			t.Errorf("GET /jwks after one reload interval has kids %q, want %q", got, want)
		}
		if slices.Contains(before, added) || strings.TrimSpace(added) == "" {
			t.Errorf("AddKey() kid = %q, want one distinct from %q", added, before)
		}
	})
}
