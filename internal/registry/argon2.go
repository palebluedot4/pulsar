package registry

import (
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
		memory:  uint32(m), //nolint:gosec // G115: see above.
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

// verify reports whether password hashes to h. The comparison takes the
// same time wherever the two hashes differ.
func (h passwordHash) verify(password string) bool {
	key := argon2.IDKey([]byte(password), h.salt, h.time, h.memory, h.threads, uint32(len(h.key))) //nolint:gosec // G115: len(h.key) is the length of a decoded base64 field, far below 2^32.
	return subtle.ConstantTimeCompare(key, h.key) == 1
}
