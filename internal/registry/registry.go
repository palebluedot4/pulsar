// Package registry holds the Clients and End-Users that pulsar reads at
// startup from its registry file, as ADR 0001 decides. The file is a JSON
// document:
//
//	{
//	  "clients": [{
//	    "client_id": "rp",
//	    "token_endpoint_auth_method": "client_secret_basic",
//	    "client_secret_hash": "$argon2id$v=19$m=19456,t=2,p=1$...$...",
//	    "redirect_uris": ["https://rp.example/callback"],
//	    "post_logout_redirect_uris": ["https://rp.example/signed-out"]
//	  }],
//	  "end_users": [{
//	    "sub": "7c9e6679-7425-40de-944b-e07fc1f90ae7",
//	    "username": "alice",
//	    "password_hash": "$argon2id$v=19$m=19456,t=2,p=1$...$...",
//	    "claims": {"name": "Alice", "email": "alice@example.com"}
//	  }]
//	}
//
// A Client may list post_logout_redirect_uris, to which pulsar returns
// the End-User after logout (OpenID Connect RP-Initiated Logout 1.0 §3.1).
// Each is checked as a redirect URI is, and, as each redirect URI is,
// listed once.
//
// A Client authenticates with the token_endpoint_auth_method it registers:
// client_secret_basic or client_secret_post with a client_secret_hash,
// private_key_jwt with the public keys in jwks, or none, for a public
// Client, with neither. Each key in jwks names in alg the one algorithm it
// signs with: RS256 or PS256 for an RSA key of at least 2048 bits, ES256
// for a P-256 key. Secrets and passwords appear only as Argon2id
// hashes in the PHC string format, such as [NewClientSecret] returns for
// a secret it generates, and the reference implementation's
// `argon2 <salt> -id -e` prints for a password.
//
// The file is decoded strictly: a member pulsar does not know, a member
// given twice, or one in another case is an error, so that a misspelled
// setting is refused rather than ignored.
//
// Each Argon2id verification takes the memory its hash's m parameter asks
// for, and a registry runs at most as many at once as fill GOMAXPROCS, as
// it is when the registry is parsed, times the memory of its largest hash:
// GOMAXPROCS of the largest, as libsodium advises one per CPU core and
// Keycloak caps its own at the number of cores, and more of smaller ones.
// A verification that finds no room waits for it, for up to two seconds,
// and is then refused with [ErrBusy], so that logins and token requests
// cannot together take more memory than that
// (docs/adr/0005-logins-throttled-per-end-user-by-delay.md).
package registry

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json/v2"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/netip"
	"net/url"
	"os"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"golang.org/x/sync/semaphore"
)

// hashWait is how long a verification waits for room before it is
// refused: long enough to ride out a burst of logins, short enough that a
// replica overloaded for longer refuses requests rather than pile them up.
const hashWait = 2 * time.Second

// ErrBusy is the error of an authentication that found no room to verify
// its password or secret within two seconds, or whose context ended first.
var ErrBusy = errors.New("registry: too many passwords and secrets are being verified")

// AuthMethod is a Client's token_endpoint_auth_method.
type AuthMethod string

// The Client authentication methods pulsar supports.
const (
	ClientSecretBasic AuthMethod = "client_secret_basic"
	ClientSecretPost  AuthMethod = "client_secret_post"
	PrivateKeyJWT     AuthMethod = "private_key_jwt"
	None              AuthMethod = "none"
)

// Registry is the set of Clients and End-Users. They never change once
// loaded, and it is safe for concurrent use.
type Registry struct {
	clients   map[string]*Client  // by client_id
	endUsers  map[string]*EndUser // by Subject
	usernames map[string]*EndUser // by username

	// decoy is verified against when no End-User has the username given,
	// so that a login for a username that does not exist costs what one
	// for the first End-User does, and so what one for any End-User whose
	// hash has the same parameters does, as hashes made by one command
	// have.
	decoy passwordHash

	// hashing holds, in KiB, the memory the verifications running take,
	// and is nil if the registry has no hash to verify.
	hashing *semaphore.Weighted
}

// Client is a registered Client.
type Client struct {
	ID           string
	AuthMethod   AuthMethod
	RedirectURIs []string
	// PostLogoutRedirectURIs are where the End-User may be returned after
	// logout, each listed once; none if the Client registered none.
	PostLogoutRedirectURIs []string
	// Origins are the origins of the RedirectURIs whose scheme is http or
	// https, each once, as a browser serializes them in an Origin header
	// (RFC 6454 §6.1); a redirect URI of another scheme, as a native
	// Client uses, has none. A browser-based Client is served from the origin its
	// redirect URI names, so these are the origins it sends requests from.
	Origins []string
	// JWKS holds the public keys of a Client that authenticates with
	// private_key_jwt, and is nil for any other. Each key's Algorithm is
	// one of AssertionAlgorithms, and is the only one it is used with.
	JWKS *jose.JSONWebKeySet

	secretHash *passwordHash // for client_secret_basic and client_secret_post
}

// Public reports whether c is a public Client: one registered for the
// method none, with no credentials to authenticate with (RFC 6749 §2.1).
func (c *Client) Public() bool {
	return c.AuthMethod == None
}

// EndUser is a registered End-User.
type EndUser struct {
	Subject  string
	Username string
	Claims   Claims

	passwordHash passwordHash
}

// Claims are an End-User's standard claims (OpenID Connect Core 1.0
// §5.1), other than sub, which is the Subject.
type Claims struct {
	Name                string   `json:"name,omitzero"`
	GivenName           string   `json:"given_name,omitzero"`
	FamilyName          string   `json:"family_name,omitzero"`
	MiddleName          string   `json:"middle_name,omitzero"`
	Nickname            string   `json:"nickname,omitzero"`
	PreferredUsername   string   `json:"preferred_username,omitzero"`
	Profile             string   `json:"profile,omitzero"`
	Picture             string   `json:"picture,omitzero"`
	Website             string   `json:"website,omitzero"`
	Email               string   `json:"email,omitzero"`
	EmailVerified       *bool    `json:"email_verified,omitzero"`
	Gender              string   `json:"gender,omitzero"`
	Birthdate           string   `json:"birthdate,omitzero"`
	Zoneinfo            string   `json:"zoneinfo,omitzero"`
	Locale              string   `json:"locale,omitzero"`
	PhoneNumber         string   `json:"phone_number,omitzero"`
	PhoneNumberVerified *bool    `json:"phone_number_verified,omitzero"`
	Address             *Address `json:"address,omitzero"`
	UpdatedAt           *int64   `json:"updated_at,omitzero"`
}

// Address is the address claim's value (OpenID Connect Core 1.0 §5.1.1).
type Address struct {
	Formatted     string `json:"formatted,omitzero"`
	StreetAddress string `json:"street_address,omitzero"`
	Locality      string `json:"locality,omitzero"`
	Region        string `json:"region,omitzero"`
	PostalCode    string `json:"postal_code,omitzero"`
	Country       string `json:"country,omitzero"`
}

// file is the registry file as it is decoded.
type file struct {
	Clients  []clientEntry  `json:"clients"`
	EndUsers []endUserEntry `json:"end_users"`
}

type clientEntry struct {
	ClientID                string              `json:"client_id"`
	TokenEndpointAuthMethod AuthMethod          `json:"token_endpoint_auth_method"`
	ClientSecretHash        string              `json:"client_secret_hash"`
	JWKS                    *jose.JSONWebKeySet `json:"jwks"`
	RedirectURIs            []string            `json:"redirect_uris"`
	PostLogoutRedirectURIs  []string            `json:"post_logout_redirect_uris"`
}

type endUserEntry struct {
	Sub          string `json:"sub"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Claims       Claims `json:"claims"`
}

// Load reads and parses the registry file at path.
func Load(path string) (*Registry, error) {
	data, err := os.ReadFile(path) //nolint:gosec // G304: the operator names the file to read.
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

// Parse parses a registry file's content. It returns an error that names
// the entry and member at fault if the content is not one JSON object of
// the form the package describes, or if a client_id, Subject or username
// is not unique.
func Parse(data []byte) (*Registry, error) {
	// A pointer, so that a file holding only null, which would leave a
	// struct as it was, is told apart from an empty object.
	var f *file
	if err := json.Unmarshal(data, &f, json.RejectUnknownMembers(true)); err != nil {
		return nil, err
	}
	if f == nil {
		return nil, errors.New("the registry must be a JSON object, not null")
	}
	r := &Registry{
		clients:   make(map[string]*Client, len(f.Clients)),
		endUsers:  make(map[string]*EndUser, len(f.EndUsers)),
		usernames: make(map[string]*EndUser, len(f.EndUsers)),
	}
	for i, e := range f.Clients {
		c, err := newClient(e)
		if err != nil {
			return nil, fmt.Errorf("clients[%d] (client_id %q): %w", i, e.ClientID, err)
		}
		if _, dup := r.clients[c.ID]; dup {
			return nil, fmt.Errorf("clients[%d]: client_id %q is not unique", i, c.ID)
		}
		r.clients[c.ID] = c
	}
	for i, e := range f.EndUsers {
		u, err := newEndUser(e)
		if err != nil {
			return nil, fmt.Errorf("end_users[%d] (username %q): %w", i, e.Username, err)
		}
		if _, dup := r.endUsers[u.Subject]; dup {
			return nil, fmt.Errorf("end_users[%d]: sub %q is not unique", i, u.Subject)
		}
		if _, dup := r.usernames[u.Username]; dup {
			return nil, fmt.Errorf("end_users[%d]: username %q is not unique", i, u.Username)
		}
		r.endUsers[u.Subject] = u
		r.usernames[u.Username] = u
	}
	if len(f.EndUsers) > 0 {
		r.decoy = decoyFor(r.usernames[f.EndUsers[0].Username].passwordHash)
	}
	if largest := r.largestHash(); largest > 0 {
		r.hashing = semaphore.NewWeighted(int64(runtime.GOMAXPROCS(0)) * largest)
	}
	return r, nil
}

// largestHash returns the memory, in KiB, of the largest hash in r, or 0
// if it has none.
func (r *Registry) largestHash() int64 {
	var largest uint32
	for _, c := range r.clients {
		if c.secretHash != nil {
			largest = max(largest, c.secretHash.memory)
		}
	}
	for _, u := range r.endUsers {
		largest = max(largest, u.passwordHash.memory)
	}
	return int64(largest)
}

// verify reports whether password hashes to h, once there is room to
// verify it, and returns ErrBusy if there is none within hashWait or ctx
// ends first. With room, and before verifying, it calls admit, if not nil,
// and returns its error, if any, without verifying.
func (r *Registry) verify(ctx context.Context, h passwordHash, password string, admit func() error) (bool, error) {
	waitCtx, cancel := context.WithTimeout(ctx, hashWait)
	defer cancel()
	if err := r.hashing.Acquire(waitCtx, int64(h.memory)); err != nil {
		return false, ErrBusy
	}
	defer r.hashing.Release(int64(h.memory))
	if admit != nil {
		if err := admit(); err != nil {
			return false, err
		}
	}
	return h.verify(password), nil
}

// decoyFor returns a password hash that no password is known to match,
// with the parameters of h, so that verifying against it costs what
// verifying against h does.
func decoyFor(h passwordHash) passwordHash {
	h.salt = make([]byte, len(h.salt))
	h.key = make([]byte, len(h.key))
	_, _ = rand.Read(h.salt) // crypto/rand.Read never returns an error.
	_, _ = rand.Read(h.key)
	return h
}

func newClient(e clientEntry) (*Client, error) {
	if e.ClientID == "" {
		return nil, errors.New("client_id is required")
	}
	c := &Client{ID: e.ClientID, AuthMethod: e.TokenEndpointAuthMethod}
	var needsSecret, needsJWKS bool
	switch e.TokenEndpointAuthMethod {
	case ClientSecretBasic, ClientSecretPost:
		needsSecret = true
	case PrivateKeyJWT:
		needsJWKS = true
	case None:
	case "":
		return nil, errors.New("token_endpoint_auth_method is required")
	default:
		return nil, fmt.Errorf("token_endpoint_auth_method %q is not one of %s, %s, %s or %s",
			e.TokenEndpointAuthMethod, ClientSecretBasic, ClientSecretPost, PrivateKeyJWT, None)
	}

	switch {
	case needsSecret && e.ClientSecretHash == "":
		return nil, fmt.Errorf("client_secret_hash is required for %s", e.TokenEndpointAuthMethod)
	case !needsSecret && e.ClientSecretHash != "":
		return nil, fmt.Errorf("client_secret_hash is not allowed for %s", e.TokenEndpointAuthMethod)
	case needsSecret:
		h, err := parsePasswordHash(e.ClientSecretHash)
		if err != nil {
			return nil, fmt.Errorf("client_secret_hash: %w", err)
		}
		c.secretHash = &h
	}

	switch {
	case needsJWKS && e.JWKS == nil:
		return nil, fmt.Errorf("jwks is required for %s", PrivateKeyJWT)
	case !needsJWKS && e.JWKS != nil:
		return nil, fmt.Errorf("jwks is not allowed for %s", e.TokenEndpointAuthMethod)
	case needsJWKS:
		if err := checkJWKS(e.JWKS); err != nil {
			return nil, fmt.Errorf("jwks: %w", err)
		}
		c.JWKS = e.JWKS
	}

	// RFC 6749 §3.1.2.2: every Client registers its redirect URIs, whatever
	// its type, so that each is compared exactly as registered.
	if len(e.RedirectURIs) == 0 {
		return nil, errors.New("redirect_uris must list at least one URI")
	}
	uris, err := checkRedirectURIs("redirect_uris", e.RedirectURIs)
	if err != nil {
		return nil, err
	}
	for _, u := range uris {
		if o, ok := webOrigin(u); ok && !slices.Contains(c.Origins, o) {
			c.Origins = append(c.Origins, o)
		}
	}
	c.RedirectURIs = e.RedirectURIs

	// RP-Initiated Logout 1.0 §3 compares a post-logout redirect URI
	// exactly with one registered, as RFC 6749 §3.1.2 does a redirect URI,
	// so each is held to the same form.
	if _, err := checkRedirectURIs("post_logout_redirect_uris", e.PostLogoutRedirectURIs); err != nil {
		return nil, err
	}
	c.PostLogoutRedirectURIs = e.PostLogoutRedirectURIs
	return c, nil
}

// checkRedirectURIs checks each of list, the registry member name, as
// checkRedirectURI does, and that none is listed twice, and returns them
// parsed.
func checkRedirectURIs(name string, list []string) ([]*url.URL, error) {
	uris := make([]*url.URL, len(list))
	for i, raw := range list {
		u, err := checkRedirectURI(raw)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", name, i, err)
		}
		if slices.Contains(list[:i], raw) {
			return nil, fmt.Errorf("%s[%d]: %q is listed twice", name, i, raw)
		}
		uris[i] = u
	}
	return uris, nil
}

// defaultPort is the port each scheme a browser-based Client is served
// over implies.
var defaultPort = map[string]string{"https": "443", "http": "80"}

// webOrigin returns the origin of u, a redirect URI that checkRedirectURI
// accepted, as a browser serializes it in an Origin header (RFC 6454
// §6.1): the scheme and host in lowercase, an IP address in its shortest
// form, and the port, as a number, only if it is not the scheme's
// default. Only an http or https URI has one. An IPv4 address in a form
// other than four decimal parts, such as 127.1, is kept as it is written,
// so a request from it is refused.
func webOrigin(u *url.URL) (string, bool) {
	def, ok := defaultPort[u.Scheme] // url.Parse lowercases the scheme
	if !ok {
		return "", false
	}
	host := strings.ToLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		host = addr.String()
		if addr.Is6() {
			host = "[" + host + "]" // RFC 3986 §3.2.2
		}
	}
	port := u.Port()
	if n, err := strconv.ParseUint(port, 10, 16); err == nil {
		port = strconv.FormatUint(n, 10)
	}
	if port != "" && port != def {
		host += ":" + port
	}
	return u.Scheme + "://" + host, true
}

// AssertionAlgorithms returns the JWS algorithms with which a Client
// registered for private_key_jwt may sign its client assertions: an
// allow-list, as RFC 8725 §3.2 requires. It holds no HMAC algorithm, since
// client_secret_jwt is not offered, and never none.
func AssertionAlgorithms() []jose.SignatureAlgorithm {
	return []jose.SignatureAlgorithm{jose.RS256, jose.PS256, jose.ES256}
}

// checkJWKS checks that a Client's JWK Set holds at least one key, and
// only public signing keys that each name, in alg, the one algorithm of
// AssertionAlgorithms it is used with (RFC 8725 §3.1).
func checkJWKS(set *jose.JSONWebKeySet) error {
	if len(set.Keys) == 0 {
		return errors.New("must hold at least one key")
	}
	for i, k := range set.Keys {
		if !k.Valid() || !k.IsPublic() {
			return fmt.Errorf("keys[%d] is not a valid public key", i)
		}
		if k.Use != "" && k.Use != "sig" {
			return fmt.Errorf("keys[%d]: use %q is not sig", i, k.Use)
		}
		if err := checkAssertionKey(k); err != nil {
			return fmt.Errorf("keys[%d]: %w", i, err)
		}
	}
	return nil
}

// checkAssertionKey checks that k names an algorithm of
// AssertionAlgorithms in alg, and is a key of the type and size that
// algorithm takes.
func checkAssertionKey(k jose.JSONWebKey) error {
	// Of jose's algorithms, all but these few are refused alike.
	//
	//exhaustive:ignore
	switch alg := jose.SignatureAlgorithm(k.Algorithm); alg {
	case jose.RS256, jose.PS256:
		pub, ok := k.Key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s takes an RSA key", alg)
		}
		// RFC 7518 §3.3 and §3.5.
		if n := pub.N.BitLen(); n < 2048 {
			return fmt.Errorf("an RSA key must have at least 2048 bits, not %d", n)
		}
	case jose.ES256:
		pub, ok := k.Key.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			return fmt.Errorf("alg %s takes a P-256 key", alg)
		}
	case "":
		return errors.New("alg is required, so that the key is used with one algorithm only")
	default:
		return fmt.Errorf("alg %q is not one of %s", alg, AssertionAlgorithms())
	}
	return nil
}

// checkRedirectURI checks raw against RFC 6749 §3.1.2: an absolute URI,
// as RFC 3986 §4.3 defines it, with no fragment. A custom scheme, as a
// native app uses, is allowed; an http or https URI must name a host.
//
// url.Parse accepts characters RFC 3986 does not, such as spaces, so raw
// is first checked against the characters RFC 3986 §2 allows. It returns
// raw parsed.
func checkRedirectURI(raw string) (*url.URL, error) {
	if i := strings.IndexFunc(raw, notURIChar); i >= 0 {
		return nil, fmt.Errorf("%q is not a URI: RFC 3986 does not allow %q", raw, raw[i])
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		if ue, ok := errors.AsType[*url.Error](err); ok {
			err = ue.Err
		}
		return nil, fmt.Errorf("%q is not a URI: %w", raw, err)
	case !u.IsAbs():
		return nil, fmt.Errorf("%q is not an absolute URI", raw)
	case (u.Scheme == "https" || u.Scheme == "http") && u.Host == "":
		return nil, fmt.Errorf("%q has no host", raw)
	// The raw value is checked, because url.Parse does not record an
	// empty fragment ("https://rp.example/cb#") at all.
	case strings.Contains(raw, "#"):
		return nil, fmt.Errorf("%q must not have a fragment", raw)
	}
	return u, nil
}

// notURIChar reports whether RFC 3986 §2 allows c nowhere in a URI: it is
// none of the unreserved characters, the reserved ones, or the "%" that
// starts a percent-encoding.
func notURIChar(c rune) bool {
	switch {
	case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		return false
	case strings.ContainsRune("-._~:/?#[]@!$&'()*+,;=%", c):
		return false
	}
	return true
}

func newEndUser(e endUserEntry) (*EndUser, error) {
	if !isUUID(e.Sub) {
		return nil, fmt.Errorf("sub %q is not a UUID in its lowercase hyphenated form", e.Sub)
	}
	if e.Username == "" {
		return nil, errors.New("username is required")
	}
	h, err := parsePasswordHash(e.PasswordHash)
	if err != nil {
		return nil, fmt.Errorf("password_hash: %w", err)
	}
	return &EndUser{Subject: e.Sub, Username: e.Username, Claims: e.Claims, passwordHash: h}, nil
}

// isUUID reports whether s is a UUID in the form RFC 9562 §4 gives: 32
// lowercase hexadecimal digits in groups of 8, 4, 4, 4 and 12, separated
// by hyphens. Subjects are compared as case-sensitive strings (OpenID
// Connect Core 1.0 §2), so a UUID is accepted in this one form only, and
// two spellings of the same UUID cannot become two Subjects.
func isUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range []byte(s) {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return false
			}
		}
	}
	return true
}

// Clients returns every Client, in no particular order.
func (r *Registry) Clients() iter.Seq[*Client] {
	return maps.Values(r.clients)
}

// Client returns the Client whose client_id is id.
func (r *Registry) Client(id string) (*Client, bool) {
	c, ok := r.clients[id]
	return c, ok
}

// AuthenticateClientSecret returns the Client whose client_id and secret
// these are, if it registered method, which must be client_secret_basic
// or client_secret_post, so that a Client cannot authenticate by a method
// other than its own. The secret is checked against its Argon2id hash in
// constant time. The error is ErrBusy if there was no room to check it.
func (r *Registry) AuthenticateClientSecret(ctx context.Context, method AuthMethod, id, secret string) (*Client, bool, error) {
	c, ok := r.clients[id]
	if !ok || c.AuthMethod != method || c.secretHash == nil {
		return nil, false, nil
	}
	if match, err := r.verify(ctx, *c.secretHash, secret, nil); !match {
		return nil, false, err
	}
	return c, true, nil
}

// EndUser returns the End-User whose Subject is subject.
func (r *Registry) EndUser(subject string) (*EndUser, bool) {
	u, ok := r.endUsers[subject]
	return u, ok
}

// AuthenticateEndUser returns the End-User whose username and password
// these are. It takes as long whether or not the username exists: a
// username no End-User has is checked against a decoy hash, and never
// matches. The error is ErrBusy if there was no room to check the
// password.
//
// Once there is room, and before checking the password, it calls admit,
// if not nil, with the End-User who has the username, or nil if none does;
// if admit returns an error, it returns that error without checking the
// password. A login is counted there, so that one refused for want of
// room is not counted, and logins cannot be counted faster than they can
// be checked. admit runs while the room is held.
func (r *Registry) AuthenticateEndUser(ctx context.Context, username, password string, admit func(*EndUser) error) (*EndUser, bool, error) {
	u, ok := r.usernames[username]
	var admitHash func() error
	if admit != nil {
		admitHash = func() error { return admit(u) }
	}
	if !ok {
		if len(r.usernames) > 0 {
			if _, err := r.verify(ctx, r.decoy, password, admitHash); err != nil {
				return nil, false, err
			}
		}
		return nil, false, nil
	}
	if match, err := r.verify(ctx, u.passwordHash, password, admitHash); !match {
		return nil, false, err
	}
	return u, true, nil
}
