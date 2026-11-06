package signing

import "context"

// AddKey generates and stores a key through s, as another replica will
// when rotation (#23) exists, and returns its kid. s's own snapshot is not
// reloaded.
func AddKey(ctx context.Context, s *KeySet) (string, error) {
	key, err := s.generate()
	if err != nil {
		return "", err
	}
	if err := s.queries.InsertSigningKey(ctx, key); err != nil {
		return "", err
	}
	return key.Kid, nil
}
