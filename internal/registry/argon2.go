package registry

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Limits RFC 9106 §3.1 sets on Argon2's inputs that a PHC string carries.
const (
	minSaltSize = 8 // bytes
	minKeySize  = 4 // bytes, the tag length
)

// maxMemory is the most memory, in KiB, a hash may ask for: 2 GiB, the
// most any option RFC 9106 §4 recommends uses. A hash that asks for more
// is refused when the registry loads, rather than when a login allocates
// it.
const maxMemory = 1 << 21

// passwordHash is a parsed Argon2id hash of a password or client secret.
type passwordHash struct {
	memory  uint32 // KiB
	time    uint32 // passes
	threads uint8
	salt    []byte
	key     []byte
}

// errNotArgon2id is the error for a hash that is not even in the form
// $argon2id$v=19$m=…,t=…,p=…$salt$hash.
var errNotArgon2id = errors.New("not an Argon2id PHC string of the form $argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>")

// parsePasswordHash parses an Argon2id hash in the PHC string format, as
// the reference implementation and x/crypto's users encode it: version 19,
// the parameters m, t and p in that order and in decimal without leading
// zeros, and the salt and hash in unpadded standard base64. Its errors
// never quote the hash.
func parsePasswordHash(s string) (passwordHash, error) {
	fields := strings.Split(s, "$")
	if len(fields) != 6 || fields[0] != "" || fields[1] != "argon2id" || fields[2] != "v=19" {
		return passwordHash{}, errNotArgon2id
	}
	params := strings.Split(fields[3], ",")
	if len(params) != 3 {
		return passwordHash{}, errNotArgon2id
	}
	m, errM := param(params[0], "m", 32)
	t, errT := param(params[1], "t", 32)
	p, errP := param(params[2], "p", 8)
	if err := errors.Join(errM, errT, errP); err != nil {
		return passwordHash{}, err
	}
	switch {
	case t < 1:
		return passwordHash{}, errors.New("t must be at least 1")
	case p < 1:
		return passwordHash{}, errors.New("p must be at least 1")
	case m < 8*p:
		return passwordHash{}, errors.New("m must be at least 8 times p")
	case m > maxMemory:
		return passwordHash{}, fmt.Errorf("m must be at most %d KiB (2 GiB)", maxMemory)
	}
	salt, err := base64.RawStdEncoding.Strict().DecodeString(fields[4])
	if err != nil {
		return passwordHash{}, errors.New("the salt is not unpadded standard base64")
	}
	key, err := base64.RawStdEncoding.Strict().DecodeString(fields[5])
	if err != nil {
		return passwordHash{}, errors.New("the hash is not unpadded standard base64")
	}
	if len(salt) < minSaltSize {
		return passwordHash{}, fmt.Errorf("the salt must be at least %d bytes", minSaltSize)
	}
	if len(key) < minKeySize {
		return passwordHash{}, fmt.Errorf("the hash must be at least %d bytes", minKeySize)
	}
	// param has checked that each fits the size it is converted to.
	return passwordHash{
		memory:  uint32(m),
		time:    uint32(t), //nolint:gosec // G115: see above.
		threads: uint8(p),  //nolint:gosec // G115: see above.
		salt:    salt,
		key:     key,
	}, nil
}

// param parses one name=value parameter of a PHC string: an unsigned
// decimal of at most bits bits, in its shortest form.
func param(s, name string, bits int) (uint64, error) {
	v, ok := strings.CutPrefix(s, name+"=")
	if !ok {
		return 0, errNotArgon2id
	}
	n, err := strconv.ParseUint(v, 10, bits)
	if err != nil || strconv.FormatUint(n, 10) != v {
		return 0, fmt.Errorf("%s is not a decimal number below 2^%d without leading zeros", name, bits)
	}
	return n, nil
}

// encode returns h in the PHC string format that parsePasswordHash parses.
// It is not a String method, so that formatting a hash for a log or an
// error cannot print it by accident.
func (h passwordHash) encode() string {
	enc := base64.RawStdEncoding.EncodeToString
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s", h.memory, h.time, h.threads, enc(h.salt), enc(h.key))
}

// clientSecretSize is the size of a Client secret NewClientSecret
// generates: 256 bits, so that guessing one is as unlikely as guessing a
// code (RFC 6749 §10.10).
const clientSecretSize = 32 // bytes

// The Argon2id parameters of the hash NewClientSecret returns: OWASP's
// minimum of 19 MiB over two passes in one lane, and the salt and tag
// sizes RFC 9106 §4 recommends. A Client secret's 256 random bits guard
// it, not the work factor, so the cheapest setting OWASP accepts is
// chosen: it keeps down the memory that each token request authenticated
// by the secret takes (docs/research/client-secrets.md).
const (
	clientSecretMemory  = 19456 // KiB
	clientSecretTime    = 2     // passes
	clientSecretThreads = 1
	clientSecretSalt    = 16 // bytes
	clientSecretKey     = 32 // bytes
)

// NewClientSecret returns a new Client secret and its Argon2id hash in
// the PHC string format, for a registry file's client_secret_hash. The
// secret is clientSecretSize bytes from crypto/rand in unpadded base64url,
// which form-encoding leaves as it is, so that a Client that skips that
// step for client_secret_basic still authenticates.
func NewClientSecret() (secret, hash string) {
	b := make([]byte, clientSecretSize)
	salt := make([]byte, clientSecretSalt)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error.
	_, _ = rand.Read(salt)
	secret = base64.RawURLEncoding.EncodeToString(b)
	h := passwordHash{
		memory:  clientSecretMemory,
		time:    clientSecretTime,
		threads: clientSecretThreads,
		salt:    salt,
	}
	h.key = h.derive(secret, clientSecretKey)
	return secret, h.encode()
}

// derive returns the size-byte Argon2id hash of password under h's
// parameters and salt.
func (h passwordHash) derive(password string, size uint32) []byte {
	return argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, size)
}

// verify reports whether password hashes to h. The comparison takes the
// same time wherever the two hashes differ.
func (h passwordHash) verify(password string) bool {
	key := h.derive(password, uint32(len(h.key))) //nolint:gosec // G115: len(h.key) is the length of a decoded base64 field, far below 2^32.
	return subtle.ConstantTimeCompare(key, h.key) == 1
}
