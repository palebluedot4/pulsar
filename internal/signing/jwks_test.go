package signing_test

import (
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"maps"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/postgres/postgrestest"
	"github.com/palebluedot4/pulsar/internal/signing"
)

// secret stands in for PULSAR_SECRET.
var secret = config.Secret{1, 2, 3}

// load returns a key set for pool, loaded.
func load(t *testing.T, pool *pgxpool.Pool) *signing.KeySet {
	t.Helper()
	keys := signing.New(pool, secret)
	if err := keys.Load(t.Context()); err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	return keys
}

// getJWKS sends GET /jwks to the JWK Set handler of keys and returns the
// response.
func getJWKS(t *testing.T, keys *signing.KeySet) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/jwks", http.NoBody)
	keys.HandleJWKS().ServeHTTP(rec, req)
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

// sortedKids returns the kid of each key in set, sorted.
func sortedKids(set jwkSet) []string {
	var kids []string
	for _, key := range set.Keys {
		kids = append(kids, key["kid"])
	}
	slices.Sort(kids)
	return kids
}

// REQ-JWK-1, REQ-JWK-3, REQ-JWK-4, REQ-JWA-1, REQ-JWA-3, REQ-JWA-4,
// REQ-JWA-5, REQ-DISC-18: the JWK Set holds the RSA public key, of 2048
// bits, with "kty", "n" and "e" in their minimal form, its "use", "alg"
// and a "kid" that is its RFC 7638 thumbprint, and no private member.
func TestJWKS(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.NewDatabase(t))
	rec := getJWKS(t, load(t, pool))

	wantHeader := map[string]string{
		"Content-Type":  "application/json",
		"Cache-Control": "public, max-age=60",
		// Nothing in #13 asks for CORS on the JWK Set, so none is sent.
		"Access-Control-Allow-Origin": "",
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
// not served, and the refusal is not cached. It cites no requirement: no
// clause in scope says what an OP answers before it has keys.
func TestJWKSBeforeLoad(t *testing.T) {
	t.Parallel()

	pool := postgrestest.Open(t, postgrestest.UnreachableURL(t))
	rec := getJWKS(t, signing.New(pool, secret))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("GET /jwks before Load status = %d, want %d", rec.Code, http.StatusServiceUnavailable)
	}
	if got, want := rec.Header().Get("Cache-Control"), "no-store"; got != want {
		t.Errorf("GET /jwks before Load Cache-Control = %q, want %q", got, want)
	}
}

// REQ-JWA-2: a JWS signed through the active key's crypto.Signer, as
// RS256 defines, verifies against the published JWK Set.
//
// The test signs through Active itself: nothing pulsar serves signs yet,
// until the token endpoint (#17) issues ID Tokens.
func TestSignatureVerifiesAgainstJWKS(t *testing.T) {
	t.Parallel()

	keys := load(t, postgrestest.Open(t, postgrestest.NewDatabase(t)))
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
	if err := json.Unmarshal(getJWKS(t, keys).Body.Bytes(), &set); err != nil {
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

// REQ-JWK-2: a key that another process stores, as `pulsar keys rotate`
// does, appears in this replica's JWK Set after one reload interval, not
// before, under a kid of its own.
func TestJWKSReloadsKeyFromAnotherReplica(t *testing.T) {
	t.Parallel()

	databaseURL := postgrestest.ResolveHost(t, postgrestest.NewDatabase(t))
	synctest.Test(t, func(t *testing.T) {
		r := startReplica(t, databaseURL)
		before := sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))
		added, err := signing.New(r.pool, secret).Rotate(t.Context())
		if err != nil {
			t.Fatalf("Rotate() error = %v", err)
		}
		if slices.Contains(before, added.KID) {
			t.Fatalf("GET /jwks before Rotate() has kids %q, want none of them %q", before, added.KID)
		}

		time.Sleep(signing.ReloadInterval - time.Nanosecond)
		synctest.Wait()
		if diff := cmp.Diff(before, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
			t.Errorf("GET /jwks just before one reload interval kids mismatch (-want +got):\n%s", diff)
		}

		time.Sleep(time.Nanosecond)
		synctest.Wait()
		want := slices.Sorted(slices.Values(append(slices.Clone(before), added.KID)))
		if diff := cmp.Diff(want, sortedKids(decodeJWKS(t, getJWKS(t, r.KeySet)))); diff != "" {
			t.Errorf("GET /jwks after one reload interval kids mismatch (-want +got):\n%s", diff)
		}
	})
}
