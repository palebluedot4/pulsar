// Package oidc serves the OpenID Connect protocol endpoints.
package oidc

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// Endpoint paths, relative to the issuer. Every endpoint URL pulsar
// publishes is the issuer followed by one of these.
const (
	discoveryPath     = "/.well-known/openid-configuration"
	authorizationPath = "/authorize"
	tokenPath         = "/token"
	userinfoPath      = "/userinfo"
	jwksPath          = "/jwks"
)

// discoveryCacheControl lets Clients cache the discovery document. It
// changes only when pulsar is redeployed with a new configuration.
const discoveryCacheControl = "public, max-age=3600"

// metadata is the OpenID Provider Metadata of OpenID Connect Discovery 1.0
// §3, with the RFC 8414 and RFC 9207 additions pulsar supports.
type metadata struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	UserinfoEndpoint                           string   `json:"userinfo_endpoint"`
	JWKSURI                                    string   `json:"jwks_uri"`
	ScopesSupported                            []string `json:"scopes_supported"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	ResponseModesSupported                     []string `json:"response_modes_supported"`
	GrantTypesSupported                        []string `json:"grant_types_supported"`
	SubjectTypesSupported                      []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported           []string `json:"id_token_signing_alg_values_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
	ClaimsSupported                            []string `json:"claims_supported"`
	ClaimsParameterSupported                   bool     `json:"claims_parameter_supported"`
	RequestParameterSupported                  bool     `json:"request_parameter_supported"`
	// The default is true (Discovery §3), so false must be sent.
	RequestURIParameterSupported               bool `json:"request_uri_parameter_supported"`
	AuthorizationResponseISSParameterSupported bool `json:"authorization_response_iss_parameter_supported"`
}

// DiscoveryPath returns the path at which the discovery document for issuer
// is served: the issuer's path, without a terminating slash, followed by
// /.well-known/openid-configuration (Discovery §4.1).
func DiscoveryPath(issuer *url.URL) string {
	return strings.TrimSuffix(issuer.EscapedPath(), "/") + discoveryPath
}

// HandleDiscovery serves the discovery document for issuer, which must
// already be a valid Issuer Identifier. The document never changes, so it
// is encoded once.
func HandleDiscovery(issuer *url.URL) http.Handler {
	base := strings.TrimSuffix(issuer.String(), "/")
	body, err := json.Marshal(metadata{
		Issuer:                            issuer.String(),
		AuthorizationEndpoint:             base + authorizationPath,
		TokenEndpoint:                     base + tokenPath,
		UserinfoEndpoint:                  base + userinfoPath,
		JWKSURI:                           base + jwksPath,
		ScopesSupported:                   []string{"openid", "profile", "email", "address", "phone"},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code"},
		SubjectTypesSupported:             []string{"public"},
		IDTokenSigningAlgValuesSupported:  []string{"RS256"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "private_key_jwt", "none"},
		// Asymmetric algorithms only, as RFC 8725 §3.1 asks of an
		// allow-list; never none (Discovery §3).
		TokenEndpointAuthSigningAlgValuesSupported: []string{"RS256", "PS256", "ES256"},
		CodeChallengeMethodsSupported:              []string{"S256"},
		ClaimsSupported: []string{
			// Claims of the ID Token (Core §2).
			"sub", "iss", "aud", "exp", "iat", "auth_time", "nonce",
			// Standard Claims (Core §5.1), as the registry may declare them.
			"name", "given_name", "family_name", "middle_name", "nickname",
			"preferred_username", "profile", "picture", "website",
			"email", "email_verified", "gender", "birthdate", "zoneinfo",
			"locale", "phone_number", "phone_number_verified", "address",
			"updated_at",
		},
		ClaimsParameterSupported:                   true,
		RequestParameterSupported:                  false,
		RequestURIParameterSupported:               false,
		AuthorizationResponseISSParameterSupported: true,
	})
	if err != nil {
		// Strings, booleans and string slices always encode.
		panic(fmt.Sprintf("oidc: encode discovery document: %v", err))
	}
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "application/json")
		h.Set("Cache-Control", discoveryCacheControl)
		// The document is public; browser-based Clients may read it
		// (Discovery §4).
		h.Set("Access-Control-Allow-Origin", "*")
		_, _ = w.Write(body) // A failed write means the Client has gone.
	})
}
