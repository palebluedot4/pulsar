// Package signing holds pulsar's signing keys, as ADR 0003 decides: it
// generates the first key, stores every key in PostgreSQL with its private
// half encrypted under PULSAR_SECRET, reloads them once a minute, signs
// through the active one and publishes their public halves as a JWK Set.
//
// A rotation stores a new key that every replica publishes at its next
// reload and that signs only after [ActivationDelay]. The key it replaces
// stays published until every token it signed has expired, and then
// leaves the JWK Set. Its public half still verifies an id_token_hint, and
// nothing else, until every Login Session in which it signed could have
// ended.
package signing

import (
	"context"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/palebluedot4/pulsar/internal/config"
	"github.com/palebluedot4/pulsar/internal/login"
	"github.com/palebluedot4/pulsar/internal/oidc"
	"github.com/palebluedot4/pulsar/internal/signing/internal/queries"
)

// ReloadInterval is how often a KeySet rereads its keys from the database,
// so that a key another replica stores is published here too.
const ReloadInterval = time.Minute

// jwksCacheLifetime is how long Clients may cache the JWK Set: one reload
// interval. [ActivationDelay] includes it, so that every JWK Set a Client
// holds by the time a new key signs has it; at a minute that delay is two,
// a fifth of the token lifetime.
const jwksCacheLifetime = time.Minute

// jwksCacheControl is the Cache-Control of the JWK Set.
var jwksCacheControl = "public, max-age=" + strconv.Itoa(int(jwksCacheLifetime/time.Second))

// ActivationDelay is how long after [KeySet.Rotate] stores a key it starts
// signing: one reload interval, by which every replica that reloads on
// time publishes it, plus the JWK Set's cache lifetime, by which every
// JWK Set a Client cached before then has expired. It is counted by the
// clock of the process that stores the key, and compared with each
// replica's own, so it holds as long as their clocks agree.
const ActivationDelay = ReloadInterval + jwksCacheLifetime

// retention is how long a key stays published once the next key's time to
// sign has come. A replica that has loaded the next key stops signing with
// the old one at that time, by its own clock, and a token it signed is
// valid for at most the token lifetime. The reload interval added is a
// margin, as #23 asks: for a replica whose clock is up to that much
// behind, or that loads the next key up to that much after its time.
const retention = ReloadInterval + oidc.TokenLifetime

// hintRetention is how long a key verifies an id_token_hint once the next
// key's time to sign has come: the longest a Login Session in which it
// signed an ID token can last, so that the Client can still log the
// End-User out with that ID token (OpenID Connect RP-Initiated Logout 1.0
// §2), plus the reload interval that [retention] adds, for the same
// reason.
const hintRetention = ReloadInterval + login.SessionLifetime

// algorithm is the JWS algorithm every key signs with: RS256, which
// OpenID Connect Core 1.0 §15.1 requires an OP to support.
const algorithm = jose.RS256

// keyBits is the size of a generated RSA key: the minimum RFC 7518 §3.3
// allows for RS256.
const keyBits = 2048

// GenerationLockID is the PostgreSQL transaction-level advisory lock under
// which a replica stores the first key, so that replicas starting together
// store one. Its value is arbitrary and differs from goose's migration
// lock; it must not change between releases, since replicas of two
// releases must exclude each other during a rolling deploy.
const GenerationLockID int64 = 0x70756c7361726b // "pulsark"

// encryptionKeyInfo labels the key HKDF derives from PULSAR_SECRET for
// sealing private keys, so that a key derived from the secret for any
// other purpose differs from it.
const encryptionKeyInfo = "pulsar signing key encryption"

// encryptionKeySize is the size of the key that seals private keys: 32
// bytes, for AES-256.
const encryptionKeySize = 32

// errNotLoaded is returned by [KeySet.Active] before the key set is loaded.
var errNotLoaded = errors.New("signing: the key set is not loaded yet")

// errNoKey is returned when the database holds no key to load.
var errNoKey = errors.New("signing: the database holds no signing key")

// Key is a signing key: a [crypto.Signer] that signs with RS256, and the
// kid that names its public half in the JWK Set.
type Key struct {
	KID string
	crypto.Signer
}

// KeySet is the set of signing keys stored in a database. It is empty
// until [KeySet.Load] succeeds; it is safe for concurrent use.
type KeySet struct {
	db      *pgxpool.Pool
	queries *queries.Queries
	aead    cipher.AEAD
	loaded  atomic.Pointer[snapshot]
}

// snapshot is the key set as it was last loaded: the keys it publishes,
// and the public halves of those that verify an id_token_hint.
type snapshot struct {
	keys    map[string]*rsa.PrivateKey // by kid
	hints   map[string]hintKey         // by kid; the published keys among them
	signers []signer                   // in the order they start signing
	jwks    []byte                     // the encoded JWK Set
}

// hintKey is the public half of a key that verifies an id_token_hint, and
// the time from which it no longer does; zero if there is none yet.
type hintKey struct {
	public *rsa.PublicKey
	until  time.Time
}

// signer is a published key and when it starts signing.
type signer struct {
	Key
	from time.Time
}

// New returns an empty key set for the database behind db, whose private
// keys are encrypted under a key derived from secret.
func New(db *pgxpool.Pool, secret config.Secret) *KeySet {
	key, err := hkdf.Key(sha256.New, secret[:], nil, encryptionKeyInfo, encryptionKeySize)
	if err != nil {
		panic(fmt.Sprintf("signing: derive encryption key: %v", err)) // HKDF-SHA256 can derive a key of this size from any secret.
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(fmt.Sprintf("signing: %v", err)) // The key has AES-256's size.
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		panic(fmt.Sprintf("signing: %v", err)) // AES has GCM's block size.
	}
	return &KeySet{db: db, queries: queries.New(db), aead: aead}
}

// Load reads the key set from the database, first generating and storing
// a key if the database holds none. Replicas loading an empty database
// together store one key between them.
//
// It fails if a stored key cannot be decrypted, which happens when
// PULSAR_SECRET is not the secret the key was stored under.
func (s *KeySet) Load(ctx context.Context) error {
	if err := s.ensureKey(ctx); err != nil {
		return err
	}
	return s.reload(ctx)
}

// Run reloads the key set every [ReloadInterval] until ctx is done. A
// failed reload is logged and the keys last loaded are kept, so a replica
// that loses PostgreSQL goes on publishing and signing with them; its
// readiness check fails meanwhile.
func (s *KeySet) Run(ctx context.Context, logger *slog.Logger) {
	ticker := time.NewTicker(ReloadInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.reload(ctx); err != nil && ctx.Err() == nil {
				logger.ErrorContext(ctx, "reload signing keys", "error", err)
			}
		}
	}
}

// Rotated is a key that [KeySet.Rotate] stored.
type Rotated struct {
	KID string
	// SignsFrom is when the key starts signing, by the clock of the
	// process that stored it.
	SignsFrom time.Time
}

// Rotate generates and stores a new key, which every replica publishes at
// its next reload and which signs from [ActivationDelay] after now. The
// key set need not be loaded; Rotate loads it.
//
// It fails if the database holds no key yet, since pulsar has then never
// started against it, and if a key it loads cannot be decrypted, since
// PULSAR_SECRET is then not the secret the keys were stored under, and no
// replica could decrypt a key stored under it.
func (s *KeySet) Rotate(ctx context.Context) (Rotated, error) {
	if err := s.reload(ctx); errors.Is(err, errNoKey) {
		return Rotated{}, fmt.Errorf("%w; start pulsar against it first, which generates one", err)
	} else if err != nil {
		return Rotated{}, err
	}
	key, err := s.generate(ActivationDelay)
	if err != nil {
		return Rotated{}, err
	}
	if err := s.queries.InsertSigningKey(ctx, key); err != nil {
		return Rotated{}, fmt.Errorf("store signing key: %w", err)
	}
	return Rotated{KID: key.Kid, SignsFrom: key.ActivatesAt}, nil
}

// Active returns the key to sign with: of the keys last loaded whose time
// to sign has come, by this replica's clock, the last to start, ties
// broken by kid. A replica therefore switches to a new key when its time
// comes, whether or not a reload succeeds then. If no key's time has come,
// as when the clock of the replica that generated the first key runs ahead
// of this one's, it is the first to start. Active returns an error before
// the key set is loaded.
func (s *KeySet) Active() (Key, error) {
	snap := s.loaded.Load()
	if snap == nil {
		return Key{}, errNotLoaded
	}
	now := time.Now()
	active := snap.signers[0]
	for _, k := range snap.signers[1:] {
		if k.from.After(now) {
			break
		}
		active = k
	}
	return active.Key, nil
}

// SignJWT returns a JWT in the JWS Compact Serialization whose claims are
// claims, encoded as JSON, signed with the active key. Its header names
// the key's kid, and typ as its type.
func (s *KeySet) SignJWT(typ string, claims any) (string, error) {
	key, err := s.Active()
	if err != nil {
		return "", err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("signing: encode claims: %w", err)
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: algorithm, Key: jose.JSONWebKey{Key: key.Signer, KeyID: key.KID}},
		(&jose.SignerOptions{}).WithType(jose.ContentType(typ)),
	)
	if err != nil {
		return "", fmt.Errorf("signing: %w", err)
	}
	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("signing: sign: %w", err)
	}
	return jws.CompactSerialize()
}

// VerifyJWT reports whether token is a JWT in the JWS Compact
// Serialization signed with RS256, never none, by the key of the set that
// its header's kid names: one the JWK Set publishes. If it is, VerifyJWT
// returns its header's typ and its claims, as JSON. Before the key set is
// loaded, no token verifies.
func (s *KeySet) VerifyJWT(token string) (typ string, claims []byte, ok bool) {
	snap := s.loaded.Load()
	if snap == nil {
		return "", nil, false
	}
	return verify(token, func(kid string) *rsa.PublicKey {
		if key, ok := snap.keys[kid]; ok {
			return &key.PublicKey
		}
		return nil
	})
}

// VerifyIDTokenHint is [KeySet.VerifyJWT] for an id_token_hint, which a
// key also verifies once it has left the JWK Set, until [hintRetention]
// has passed since the next key's time to sign came, by this replica's
// clock. A Client can then log the End-User out with the ID token it was
// given until every Login Session in which that key signed has ended,
// although the key verifies nothing else.
func (s *KeySet) VerifyIDTokenHint(token string) (typ string, claims []byte, ok bool) {
	snap := s.loaded.Load()
	if snap == nil {
		return "", nil, false
	}
	now := time.Now()
	return verify(token, func(kid string) *rsa.PublicKey {
		key, ok := snap.hints[kid]
		if !ok || (!key.until.IsZero() && !now.Before(key.until)) {
			return nil
		}
		return key.public
	})
}

// verify reports whether token is a JWT in the JWS Compact Serialization
// signed with RS256, never none, by the public key that keyFor returns
// for its header's kid, or nil if none may verify it. If it is, verify
// returns its header's typ and its claims, as JSON.
func verify(token string, keyFor func(kid string) *rsa.PublicKey) (typ string, claims []byte, ok bool) {
	jws, err := jose.ParseSignedCompact(token, []jose.SignatureAlgorithm{algorithm})
	if err != nil {
		return "", nil, false
	}
	header := jws.Signatures[0].Header // A compact JWS has exactly one.
	key := keyFor(header.KeyID)
	if key == nil {
		return "", nil, false
	}
	claims, err = jws.Verify(key)
	if err != nil {
		return "", nil, false
	}
	typ, _ = header.ExtraHeaders[jose.HeaderType].(string)
	return typ, claims, true
}

// HandleJWKS serves the public halves of the keys as a JWK Set (RFC 7517
// §5), each with its kid, use and alg. Before the key set is loaded it
// answers 503, which no cache may keep.
//
// The JWK Set is public, so any origin may read it, as a browser-based
// Client does to verify an ID token (RFC 10017 §6.3.3.4). The header is
// sent on every response, whatever its origin, so that no response varies
// by it (Fetch, "CORS protocol and HTTP caches").
func (s *KeySet) HandleJWKS() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Access-Control-Allow-Origin", "*")
		snap := s.loaded.Load()
		if snap == nil {
			h.Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", jwksCacheControl)
		_, _ = w.Write(snap.jwks) // A failed write means the Client has gone.
	})
}

// ensureKey generates and stores a key if the database holds none.
func (s *KeySet) ensureKey(ctx context.Context) error {
	has, err := s.queries.HasSigningKey(ctx)
	if err != nil {
		return fmt.Errorf("look up signing keys: %w", err)
	}
	if has {
		return nil
	}
	// The key is generated before the lock is taken, so that the lock is
	// held for two queries rather than a key generation. A replica that
	// finds a key stored once it holds the lock discards its own.
	// The first key signs at once: no JWK Set has been published, so
	// there is none for it to be missing from.
	key, err := s.generate(0)
	if err != nil {
		return err
	}
	// Read committed whatever the database's default, so that the recheck
	// sees a key committed while this transaction waited for the lock.
	// Under repeatable read the snapshot is taken by the statement that
	// waits, so the recheck would miss it; under serializable one replica's
	// insert would fail.
	err = pgx.BeginTxFunc(ctx, s.db, pgx.TxOptions{IsoLevel: pgx.ReadCommitted}, func(tx pgx.Tx) error {
		q := s.queries.WithTx(tx)
		if err := q.LockSigningKeyGeneration(ctx, GenerationLockID); err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		has, err := q.HasSigningKey(ctx)
		if err != nil || has {
			return err
		}
		return q.InsertSigningKey(ctx, key)
	})
	if err != nil {
		return fmt.Errorf("store signing key: %w", err)
	}
	return nil
}

// generate generates a key and returns it as a row to store, sealed,
// dated now and signing from delay after now.
func (s *KeySet) generate(delay time.Duration) (queries.InsertSigningKeyParams, error) {
	key, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return queries.InsertSigningKeyParams{}, fmt.Errorf("generate signing key: %w", err)
	}
	kid, err := thumbprint(&key.PublicKey)
	if err != nil {
		return queries.InsertSigningKeyParams{}, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return queries.InsertSigningKeyParams{}, fmt.Errorf("encode signing key: %w", err)
	}
	now := time.Now()
	return queries.InsertSigningKeyParams{
		Kid: kid,
		// The nonce is nil because the AEAD draws a random one itself and
		// prepends it to the ciphertext ([cipher.NewGCMWithRandomNonce]).
		SealedPrivateKey: s.aead.Seal(nil, nil, der, []byte(kid)), //nolint:gosec // G407: see above; no nonce is hardcoded.
		CreatedAt:        now,
		ActivatesAt:      now.Add(delay),
	}, nil
}

// reload reads every stored key and replaces the snapshot. A key already
// loaded is not decrypted again: a row is never updated.
//
// A key is retired once [retention] has passed since the next key's time
// to sign came: it is then neither published nor accepted, and its private
// half is not kept. Its public half verifies an id_token_hint until
// [hintRetention] has passed since that time; after that, the key is not
// decrypted at all. Its row stays.
func (s *KeySet) reload(ctx context.Context) error {
	rows, err := s.queries.ListSigningKeys(ctx)
	if err != nil {
		return fmt.Errorf("read signing keys: %w", err)
	}
	if len(rows) == 0 {
		return errNoKey
	}
	previous := s.loaded.Load()
	if previous == nil {
		previous = &snapshot{}
	}

	now := time.Now()
	keys := make(map[string]*rsa.PrivateKey)
	hints := make(map[string]hintKey)
	var signers []signer
	var set jose.JSONWebKeySet
	// Rows come in the order they start signing, so a key's successor is
	// the next row, and the last key is never retired.
	for i, row := range rows {
		var until time.Time
		published := true
		if i+1 < len(rows) {
			next := rows[i+1].ActivatesAt
			until = next.Add(hintRetention)
			if !now.Before(until) {
				continue
			}
			published = now.Before(next.Add(retention))
		}
		if !published {
			public := previous.hints[row.Kid].public
			if public == nil {
				key, err := s.open(row.Kid, row.SealedPrivateKey)
				if err != nil {
					return fmt.Errorf("signing key %s: %w", row.Kid, err)
				}
				public = &key.PublicKey
			}
			hints[row.Kid] = hintKey{public: public, until: until}
			continue
		}
		key, ok := previous.keys[row.Kid]
		if !ok {
			key, err = s.open(row.Kid, row.SealedPrivateKey)
			if err != nil {
				return fmt.Errorf("signing key %s: %w", row.Kid, err)
			}
		}
		keys[row.Kid] = key
		hints[row.Kid] = hintKey{public: &key.PublicKey, until: until}
		signers = append(signers, signer{KID: row.Kid, Signer: key, from: row.ActivatesAt})
		set.Keys = append(set.Keys, jose.JSONWebKey{
			Key:       &key.PublicKey,
			KeyID:     row.Kid,
			Algorithm: string(algorithm),
			Use:       "sig",
		})
	}
	jwks, err := json.Marshal(set)
	if err != nil {
		return fmt.Errorf("encode JWK Set: %w", err)
	}
	s.loaded.Store(&snapshot{keys: keys, hints: hints, signers: signers, jwks: jwks})
	return nil
}

// open decrypts a stored private key and checks that it is an RSA key of
// at least keyBits whose thumbprint is kid.
func (s *KeySet) open(kid string, sealed []byte) (*rsa.PrivateKey, error) {
	der, err := s.aead.Open(nil, nil, sealed, []byte(kid))
	if err != nil {
		// GCM authenticates the ciphertext and kid together, so this is
		// the only failure a wrong secret or an altered row can cause.
		return nil, errors.New("cannot decrypt it: PULSAR_SECRET is not the secret it was stored under, or its row was altered")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok || key.N.BitLen() < keyBits {
		return nil, fmt.Errorf("not an RSA key of at least %d bits", keyBits)
	}
	got, err := thumbprint(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	if got != kid {
		return nil, errors.New("its kid is not its thumbprint")
	}
	return key, nil
}

// thumbprint returns the kid of a public key: its JWK Thumbprint (RFC 7638
// §3) with SHA-256, base64url-encoded, as RFC 7638 §1 suggests. Distinct
// keys therefore get distinct kids, and any party can recompute one.
func thumbprint(pub *rsa.PublicKey) (string, error) {
	jwk := jose.JSONWebKey{Key: pub}
	b, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("compute thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
