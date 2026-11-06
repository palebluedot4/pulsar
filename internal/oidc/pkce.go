package oidc

import (
	"crypto/sha256"
	"encoding/base64"
)

// Bounds on the length of a code_verifier or code_challenge (RFC 7636
// §4.1, §4.2).
const (
	minPKCELen = 43
	maxPKCELen = 128
)

// codeChallenge returns the S256 code challenge of a PKCE code_verifier:
// BASE64URL-ENCODE(SHA256(ASCII(code_verifier))) (RFC 7636 §4.2). pulsar
// supports S256 only (ADR 0002).
func codeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validPKCEValue reports whether s has the form RFC 7636 gives both a
// code_verifier (§4.1) and a code_challenge (§4.2): 43 to 128 of the
// unreserved characters of RFC 3986 §2.3. The lower bound on a verifier
// is what keeps it from being guessed (§7.1).
func validPKCEValue(s string) bool {
	if len(s) < minPKCELen || len(s) > maxPKCELen {
		return false
	}
	for _, c := range []byte(s) {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9':
		case c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}
