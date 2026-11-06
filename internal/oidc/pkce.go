package oidc

import (
	"crypto/sha256"
	"encoding/base64"
)

// PKCE (RFC 7636) binds an authorization code to the Client instance that
// asked for it: the authorization request carries a code_challenge, and
// the token request must carry the code_verifier it was made from.
// pulsar supports S256 only (ADR 0002).

// Bounds on the length of a code_verifier (RFC 7636 §4.1).
const (
	minVerifierLen = 43
	maxVerifierLen = 128
)

// codeChallenge returns the S256 code challenge of verifier:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) (RFC 7636 §4.2).
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validChallenge reports whether challenge is one that codeChallenge can
// return: the base64url encoding of a SHA-256 hash, without padding. Any
// other could match no code_verifier.
func validChallenge(challenge string) bool {
	b, err := base64.RawURLEncoding.Strict().DecodeString(challenge)
	return err == nil && len(b) == sha256.Size
}

// validVerifier reports whether verifier has the form RFC 7636 §4.1 gives
// a code_verifier: 43 to 128 of the unreserved characters of RFC 3986
// §2.3. The lower bound is what makes a verifier impractical to guess
// (RFC 7636 §7.1), so a shorter one is refused even if its challenge
// matches.
func validVerifier(verifier string) bool {
	if len(verifier) < minVerifierLen || len(verifier) > maxVerifierLen {
		return false
	}
	for _, c := range []byte(verifier) {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
