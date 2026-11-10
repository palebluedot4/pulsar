// Package api is an example Resource Server: an API that accepts the
// access tokens pulsar issues for it, and verifies each one itself
// against pulsar's JWK Set, as RFC 9068 §4 describes. It reaches pulsar
// only over the network, and learns everything but pulsar's issuer and
// its own identifier from pulsar's discovery document.
//
// It keeps each End-User's notes in memory:
//
//	GET  /notes  the End-User's notes; needs the scope notes:read
//	POST /notes  adds a note, from {"text": "..."}; needs notes:write
package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

// The scopes the API's routes need, as pulsar's registry lists them for
// its Resource Server.
const (
	ScopeRead  = "notes:read"
	ScopeWrite = "notes:write"
)

// maxNoteBytes bounds the body of a request that adds a note.
const maxNoteBytes = 4 << 10

// Config is what the API needs to know: pulsar, and itself.
type Config struct {
	// Issuer is pulsar's Issuer Identifier.
	Issuer string
	// Identifier is the API's identifier, as pulsar's registry lists its
	// Resource Server: the resource parameter a Client sends for a token
	// for the API, and the aud of every token the API accepts.
	Identifier string
	// Now returns the time against which a token's exp is checked; the
	// clock, if nil. A test sets it to see an expired token refused.
	Now func() time.Time
}

// Server is the API. It is an http.Handler.
type Server struct {
	cfg  Config
	keys *oidc.RemoteKeySet
	mux  *http.ServeMux

	mu    sync.Mutex
	notes map[string][]string // by the End-User's sub
}

// New discovers pulsar's JWK Set from its discovery document at
// cfg.Issuer, and returns the API. ctx is used for discovery and, for as
// long as the API serves, for fetching the JWK Set; an HTTP client set in
// it by oidc.ClientContext makes those requests.
func New(ctx context.Context, cfg Config) (*Server, error) {
	if cfg.Identifier == "" {
		return nil, errors.New("api: the identifier is required")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	// NewProvider refuses a discovery document whose issuer is not
	// cfg.Issuer exactly (OpenID Connect Discovery 1.0 §4.3), so the
	// jwks_uri comes from pulsar itself.
	provider, err := oidc.NewProvider(ctx, cfg.Issuer)
	if err != nil {
		return nil, fmt.Errorf("api: discover %s: %w", cfg.Issuer, err)
	}
	var meta struct {
		JWKSURI string `json:"jwks_uri"`
	}
	if err := provider.Claims(&meta); err != nil || meta.JWKSURI == "" {
		return nil, fmt.Errorf("api: the discovery document of %s has no jwks_uri", cfg.Issuer)
	}
	s := &Server{
		cfg: cfg,
		// The key set is fetched when first needed and cached. A token it
		// cannot verify with the cached keys, as one signed with a key
		// pulsar has rotated in, makes it fetch the JWK Set again, once
		// for all the requests waiting on it (OpenID Connect Core 1.0
		// §10.1.1).
		keys:  oidc.NewRemoteKeySet(ctx, meta.JWKSURI),
		mux:   http.NewServeMux(),
		notes: make(map[string][]string),
	}
	s.mux.Handle("GET /notes", s.require(ScopeRead, s.listNotes))
	s.mux.Handle("POST /notes", s.require(ScopeWrite, s.addNote))
	return s, nil
}

// ServeHTTP serves the API's routes.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

// Token is what the API uses of an access token it has verified.
type Token struct {
	Subject  string
	ClientID string
	Scopes   []string
}

// Verify verifies raw, an access token, as RFC 9068 §4 requires of a
// Resource Server, and returns its claims. Each check is one the RFC
// names; any failure is reported as invalid_token.
func (s *Server) Verify(ctx context.Context, raw string) (*Token, error) {
	// The algorithm is one the API accepts, and never none (RFC 9068 §4,
	// RFC 8725 §3.1). RS256 is the one RFC 9068 §2.1 requires every
	// authorization server and resource server to support, and the one
	// pulsar signs with.
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.RS256})
	if err != nil {
		return nil, fmt.Errorf("not a JWT signed with RS256: %w", err)
	}

	// typ is at+jwt, so that a JWT of another kind, such as an ID token,
	// is not taken for an access token (RFC 9068 §4, RFC 8725 §3.11).
	// Media types compare without regard to case (RFC 7515 §4.1.9).
	typ, _ := parsed.Headers[0].ExtraHeaders[jose.HeaderType].(string)
	if !strings.EqualFold(typ, "at+jwt") && !strings.EqualFold(typ, "application/at+jwt") {
		return nil, fmt.Errorf("typ is %q, not at+jwt", typ)
	}

	// The signature, by a key in pulsar's JWK Set (RFC 9068 §4).
	payload, err := s.keys.VerifySignature(ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("signature: %w", err)
	}
	var claims struct {
		jwt.Claims
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("claims: %w", err)
	}

	// iss is pulsar's issuer, exactly as discovered (RFC 9068 §4).
	if claims.Issuer != s.cfg.Issuer {
		return nil, fmt.Errorf("iss is %q, not %q", claims.Issuer, s.cfg.Issuer)
	}
	// aud names this API. A token pulsar issued for its own UserInfo, or
	// for another Resource Server, names something else, and is refused
	// here (RFC 9068 §4, RFC 9700 §2.3).
	if !claims.Audience.Contains(s.cfg.Identifier) {
		return nil, fmt.Errorf("aud %q does not name %q", claims.Audience, s.cfg.Identifier)
	}
	// The current time is before exp, which every access token must have
	// (RFC 9068 §2.2, §4).
	if claims.Expiry == nil {
		return nil, errors.New("no exp")
	}
	if now := s.cfg.Now(); !now.Before(claims.Expiry.Time()) {
		return nil, fmt.Errorf("expired at %s", claims.Expiry.Time().UTC().Format(time.RFC3339))
	}

	return &Token{Subject: claims.Subject, ClientID: claims.ClientID, Scopes: strings.Fields(claims.Scope)}, nil
}

// require returns a handler that serves a request with next only if it
// carries an access token for the API that grants scope, and otherwise
// answers as RFC 6750 §3 says.
func (s *Server) require(scope string, next func(http.ResponseWriter, *http.Request, *Token)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, ok := bearerToken(r)
		if !ok {
			// No token at all: a challenge without an error code (RFC 6750
			// §3, §3.1).
			challenge(w, http.StatusUnauthorized, `Bearer`)
			return
		}
		token, err := s.Verify(r.Context(), raw)
		if err != nil {
			// The reason stays in the API: the Client learns only that the
			// token is invalid (RFC 6750 §3.1).
			challenge(w, http.StatusUnauthorized, `Bearer error="invalid_token", error_description="The access token is invalid."`)
			return
		}
		if !slices.Contains(token.Scopes, scope) {
			// A valid token without the route's scope: 403, naming the
			// scope needed (RFC 6750 §3, §3.1).
			challenge(w, http.StatusForbidden, `Bearer error="insufficient_scope", scope="`+scope+`"`)
			return
		}
		next(w, r, token)
	})
}

// bearerToken returns the access token in r's Authorization header, by
// the Bearer scheme (RFC 6750 §2.1), whose name compares without regard
// to case (RFC 9110 §11.1). It reports false if there is none.
func bearerToken(r *http.Request) (string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") || token == "" {
		return "", false
	}
	return token, true
}

// challenge answers with status and the WWW-Authenticate challenge value.
func challenge(w http.ResponseWriter, status int, value string) {
	w.Header().Set("WWW-Authenticate", value)
	http.Error(w, http.StatusText(status), status)
}

// notesResponse is the body of GET /notes.
type notesResponse struct {
	Notes []string `json:"notes"`
}

// noteRequest is the body of POST /notes, and of its response.
type noteRequest struct {
	Text string `json:"text"`
}

func (s *Server) listNotes(w http.ResponseWriter, _ *http.Request, token *Token) {
	s.mu.Lock()
	notes := append([]string{}, s.notes[token.Subject]...) // a copy, never nil, so that none is []
	s.mu.Unlock()
	writeJSON(w, http.StatusOK, notesResponse{Notes: notes})
}

func (s *Server) addNote(w http.ResponseWriter, r *http.Request, token *Token) {
	var note noteRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxNoteBytes)).Decode(&note); err != nil || note.Text == "" {
		http.Error(w, `The body must be {"text": "..."}, with text not empty.`, http.StatusBadRequest)
		return
	}
	s.mu.Lock()
	s.notes[token.Subject] = append(s.notes[token.Subject], note.Text)
	s.mu.Unlock()
	writeJSON(w, http.StatusCreated, note)
}

// writeJSON answers with status and v, in JSON.
func writeJSON(w http.ResponseWriter, status int, v any) {
	b, err := json.Marshal(v)
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(append(b, '\n')) // The status is already sent; a failed write has no one to tell.
}
