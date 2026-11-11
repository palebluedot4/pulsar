package signing

// Seal encrypts der, a private key in PKCS #8, as s stores the key whose
// kid is kid, so that a test can store a key that Load must refuse.
func (s *KeySet) Seal(kid string, der []byte) []byte {
	return s.aead.Seal(nil, nil, der, []byte(kid)) //nolint:gosec // G407: the AEAD draws a random nonce itself, as generate's does.
}
