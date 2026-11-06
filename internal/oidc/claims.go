package oidc

import (
	"bytes"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"

	"github.com/palebluedot4/pulsar/internal/registry"
)

// scopeClaims are the claims that each scope value requests (OpenID
// Connect Core 1.0 §5.4). Together they are every Standard Claim (§5.1)
// but sub, and so every claim the registry may declare.
var scopeClaims = map[string][]string{
	"profile": {
		"name", "family_name", "given_name", "middle_name", "nickname",
		"preferred_username", "profile", "picture", "website", "gender",
		"birthdate", "zoneinfo", "locale", "updated_at",
	},
	"email":   {"email", "email_verified"},
	"address": {"address"},
	"phone":   {"phone_number", "phone_number_verified"},
}

// standardClaims returns the claims of scopeClaims, scope by scope in the
// order of supportedScopes.
func standardClaims() []string {
	var names []string
	for _, s := range supportedScopes {
		names = append(names, scopeClaims[s.Value]...)
	}
	return names
}

// claimScope is the scope value that requests each claim of scopeClaims.
var claimScope = func() map[string]string {
	m := make(map[string]string)
	for scope, names := range scopeClaims {
		for _, name := range names {
			m[name] = scope
		}
	}
	return m
}()

// endUserClaims returns the claims of u that the registry declares, as
// JSON decodes them into maps, strings, numbers and booleans. A claim u
// does not have is left out, rather than given as null or "" (§5.3.2).
func endUserClaims(u *registry.EndUser) (map[string]any, error) {
	data, err := json.Marshal(u.Claims)
	if err != nil {
		return nil, fmt.Errorf("encode the claims of %s: %w", u.Subject, err)
	}
	var claims map[string]any
	if err := json.Unmarshal(data, &claims); err != nil {
		return nil, fmt.Errorf("decode the claims of %s: %w", u.Subject, err)
	}
	return claims, nil
}

// claimsRequest is the claims parameter of an authorization request
// (§5.5), as pulsar keeps it with the code it issues: the claims requested
// in the ID token and from UserInfo that pulsar can release. The sub Claim
// is always both, and is not kept.
type claimsRequest struct {
	IDToken  requestedClaims `json:"id_token,omitzero"`
	UserInfo requestedClaims `json:"userinfo,omitzero"`
}

// encode returns c as it is stored with a code.
func (c claimsRequest) encode() ([]byte, error) {
	data, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("encode the claims requested: %w", err)
	}
	return data, nil
}

// decodeClaimsRequest returns the claims request that data, as encode
// stored it, holds.
func decodeClaimsRequest(data []byte) (claimsRequest, error) {
	var c claimsRequest
	if err := json.Unmarshal(data, &c); err != nil {
		return c, fmt.Errorf("decode the claims requested: %w", err)
	}
	return c, nil
}

// requestedClaims are individual claim requests (§5.5.1), by claim name.
type requestedClaims map[string]claimRequest

// encode returns rs as it is stored with an access token: a JSON object,
// {} if rs is empty.
func (rs requestedClaims) encode() ([]byte, error) {
	data, err := json.Marshal(rs)
	if err != nil {
		return nil, fmt.Errorf("encode the claims requested: %w", err)
	}
	return data, nil
}

// decodeRequestedClaims returns the claim requests that data, as
// requestedClaims.encode stored them, holds.
func decodeRequestedClaims(data []byte) (requestedClaims, error) {
	var rs requestedClaims
	if err := json.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("decode the claims requested: %w", err)
	}
	return rs, nil
}

// claimRequest is an individual claim request: the values the claim may
// be released with, by its value or values member, or nil for any.
// Whether it is Essential makes no difference: no error follows from a
// claim not returned (§5.5.1).
type claimRequest struct {
	Values []any `json:"values,omitzero"`
}

// allows reports whether the request allows the claim to be released with
// value v. Both are decoded JSON values, and are equal when their
// encodings, with object members sorted, are.
func (r claimRequest) allows(v any) bool {
	if r.Values == nil {
		return true
	}
	got, err := json.Marshal(v, json.Deterministic(true))
	if err != nil {
		return false
	}
	return slices.ContainsFunc(r.Values, func(w any) bool {
		want, err := json.Marshal(w, json.Deterministic(true))
		return err == nil && bytes.Equal(got, want)
	})
}

// release adds to dst those of all, an End-User's claims, that rs
// requests, each only if its request allows its value.
func (rs requestedClaims) release(dst, all map[string]any) {
	for name, r := range rs {
		if v, ok := all[name]; ok && r.allows(v) {
			dst[name] = v
		}
	}
}

// scopes returns the scope values that request, between them, every claim
// the request asks for, in the order of supportedScopes.
func (c claimsRequest) scopes() []string {
	requested := make(map[string]bool)
	for _, rs := range []requestedClaims{c.IDToken, c.UserInfo} {
		for name := range rs {
			requested[claimScope[name]] = true
		}
	}
	var scopes []string
	for _, s := range supportedScopes {
		if requested[s.Value] {
			scopes = append(scopes, s.Value)
		}
	}
	return scopes
}

// errClaimsParameter is returned by parseClaimsParameter for a claims
// parameter that is not of the form §5.5 gives.
var errClaimsParameter = errors.New("the claims parameter is not a claims request")

// individualRequest is an individual claim request as it is sent: null, or
// an object whose value and values members pulsar reads (§5.5.1). Its
// other members, such as essential, are ignored, as are those pulsar does
// not understand.
type individualRequest struct {
	Value  any    `json:"value"`
	Values *[]any `json:"values"`
}

// parseClaimsParameter parses raw, a claims parameter: a JSON object
// whose id_token and userinfo members, if present and not null, are
// objects whose members are individual claim requests (§5.5, §5.5.1). It
// is decoded strictly, so that no two readings of it differ: a member
// given twice is an error. Other members, and claims pulsar cannot
// release, are ignored, as §5.5 requires of what is not understood.
//
// It returns the claims requested, and, if the sub Claim is requested in
// the ID token with a value or values, the Subjects that the response may
// be about (§3.1.2.2).
func parseClaimsParameter(raw string) (req claimsRequest, subjects []string, err error) {
	var top map[string]jsontext.Value
	if err := json.Unmarshal([]byte(raw), &top); err != nil || top == nil {
		return req, nil, errClaimsParameter
	}
	for _, m := range []struct {
		name string
		dst  *requestedClaims
	}{{"id_token", &req.IDToken}, {"userinfo", &req.UserInfo}} {
		var members map[string]jsontext.Value
		if v, ok := top[m.name]; ok {
			if err := json.Unmarshal(v, &members); err != nil {
				return req, nil, errClaimsParameter
			}
		}
		for name, v := range members {
			var ind *individualRequest
			if err := json.Unmarshal(v, &ind); err != nil {
				return req, nil, errClaimsParameter
			}
			var r claimRequest
			switch {
			case ind == nil:
			case ind.Value != nil:
				r.Values = []any{ind.Value}
			case ind.Values != nil:
				r.Values = *ind.Values
				if r.Values == nil {
					r.Values = []any{} // an empty set of values, which none matches
				}
			}
			if name == "sub" && m.name == "id_token" && r.Values != nil {
				subjects = make([]string, 0, len(r.Values))
				for _, v := range r.Values {
					s, ok := v.(string)
					if !ok {
						return req, nil, errClaimsParameter
					}
					subjects = append(subjects, s)
				}
				continue
			}
			if _, ok := claimScope[name]; !ok || (r.Values != nil && len(r.Values) == 0) {
				continue
			}
			if *m.dst == nil {
				*m.dst = make(requestedClaims)
			}
			(*m.dst)[name] = r
		}
	}
	return req, subjects, nil
}
