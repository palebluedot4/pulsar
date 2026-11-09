# CORS for browser-based Clients

What the specifications in scope, the Fetch standard and two open-source
providers say about answering cross-origin requests at the token endpoint,
UserInfo and the JWK Set, for #41. Surveyed 2026-11-09 from specifications
and official source code: node-oidc-provider at commit `3ed87bef`, the
commit #41 cites, and Keycloak at commit `744bbf1f`. What hosted providers
do, and what the conformance suite checks, was surveyed earlier
([UserInfo and the claims parameter](userinfo-and-claims.md#cors-at-userinfo-and-the-token-endpoint)).
Anything not confirmed is marked **UNVERIFIED**.

## Normative text

| Source                                           | Clause   | What it says                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |
| ------------------------------------------------ | -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 10017 (BCP 212, August 2026)                 | §6.3.3.4 | "The authorization server and the resource server MUST send necessary CORS headers (defined in [Fetch]) to enable the application to make the necessary cross-origin requests." The token endpoint first, then "discovery metadata URLs, JSON Web Key Sets, dynamic client registration, revocation, introspection, or user info endpoints". The policy "can consist of a wildcard origin or a more restrictive configuration".                                                                                   |
| RFC 10017                                        | §6.3.3.4 | "During the preflight, the authorization server can only verify the provided origin, but during an actual request, the authorization server has the full request data, such as the client ID. Consequently, the authorization server can approve a known origin during the preflight but reject the actual request after comparing the origin to this specific client's list of pre-registered origins."                                                                                                          |
| OpenID Connect Discovery 1.0 (errata set 2)      | §3       | "The Token Endpoint, UserInfo Endpoint, jwks_uri endpoint, Dynamic Client Registration Endpoint, and any other endpoints directly accessed by Clients SHOULD support the use of Cross-Origin Resource Sharing (CORS) [CORS] and/or other methods as appropriate to enable JavaScript Clients and other Browser-Based Clients to access them. The use of CORS at the Authorization Endpoint is NOT RECOMMENDED as it is redirected to by the client and not directly accessed."                                    |
| OpenID Connect Discovery 1.0                     | §4       | The openid-configuration endpoint "SHOULD support the use of Cross-Origin Resource Sharing (CORS)". pulsar sends `*` there already (REQ-DISC-14).                                                                                                                                                                                                                                                                                                                                                                 |
| OpenID Connect Core 1.0 (errata set 2)           | §5.3     | "The UserInfo Endpoint SHOULD support the use of Cross-Origin Resource Sharing (CORS) [CORS] and/or other methods as appropriate to enable JavaScript Clients and other Browser-Based Clients to access it."                                                                                                                                                                                                                                                                                                      |
| RFC 9700                                         | §2.6     | "To support browser-based clients, endpoints directly accessed by such clients including the Token Endpoint, Authorization Server Metadata Endpoint, jwks_uri Endpoint, and Dynamic Client Registration Endpoint MAY support the use of Cross-Origin Resource Sharing (CORS) [WHATWG.CORS]. However, CORS MUST NOT be supported at the authorization endpoint, as the client does not access this endpoint directly; instead, the client redirects the user agent to it." Nothing else in RFC 9700 concerns CORS. |
| RFC 6749, RFC 6750, RFC 7636, RFC 8414, RFC 9207 | —        | No mention of CORS or cross-origin requests.                                                                                                                                                                                                                                                                                                                                                                                                                                                                      |

RFC 10017 is draft-ietf-oauth-browser-based-apps, published after its last
revision, -27 (2026-07-06). Its §6.3.3.4 is word for word that of -25,
which #41 quotes, but for editorial changes. The draft and the RFC put the
backend-for-frontend architecture (§6.1) ahead of the browser-based OAuth
client (§6.3), which they describe as exposed to every attack in §5.1.

Sources: <https://www.rfc-editor.org/rfc/rfc10017>,
<https://datatracker.ietf.org/doc/draft-ietf-oauth-browser-based-apps/>,
<https://openid.net/specs/openid-connect-discovery-1_0.html>,
<https://openid.net/specs/openid-connect-core-1_0.html>,
<https://www.rfc-editor.org/rfc/rfc9700#section-2.6>.

## The Fetch standard

Read from the WHATWG Fetch Living Standard as updated 2026-10-19,
<https://fetch.spec.whatwg.org/>.

- **Which requests are preflighted.** `GET`, `HEAD` and `POST` are
  CORS-safelisted methods. The safelisted request headers are `Accept`,
  `Accept-Language`, `Content-Language`, `Content-Type` and `Range`, and
  `Content-Type` only for `application/x-www-form-urlencoded`,
  `multipart/form-data` or `text/plain`. A token request from a public
  Client, a form-encoded `POST` with no `Authorization` header, is
  therefore sent without a preflight, and reaches the server whatever the
  server's policy. A UserInfo request with an `Authorization` header is
  preflighted.
- **`Authorization` must be named.** It is a "CORS non-wildcard
  request-header name": `Access-Control-Allow-Headers: *` does not allow
  it, and a preflight that does not name it fails.
- **The preflight response.** A preflight is an `OPTIONS` request with
  `Access-Control-Request-Method` and, if any, `Access-Control-Request-Headers`,
  and "never includes credentials". It succeeds only with "an ok status,
  e.g., 200 or 204" and an `Access-Control-Allow-Origin` that matches.
  `Access-Control-Max-Age` "Indicates the number of seconds (5 by
  default)" for which its result may be cached; browsers may impose a
  lower limit.
- **Every actual response needs the header.** A response to a CORS request
  "can use any status, as long as it includes the headers stated above",
  so an error response is readable by the application only if it carries
  `Access-Control-Allow-Origin`.
- **Response headers the application can read.** Beyond `Cache-Control`,
  `Content-Language`, `Content-Length`, `Content-Type`, `Expires`,
  `Last-Modified` and `Pragma`, only those named in
  `Access-Control-Expose-Headers`. `WWW-Authenticate` is not among them.
- **`*` and credentials.** `Access-Control-Allow-Origin: *` fails for a
  request whose credentials mode is `include`.
- **Caches.** "If CORS protocol requirements are more complicated than
  setting `Access-Control-Allow-Origin` to * or a static origin, `Vary` is
  to be used." For `*` or a static origin, the header is to be sent on
  every response, CORS or not, "and do not use `Vary`" (CORS protocol and
  HTTP caches, a non-normative section).

## What two providers send

Both restrict by Client at the token endpoint and UserInfo, most often to
the origins of its redirect URIs ([earlier survey](userinfo-and-claims.md#cors-at-userinfo-and-the-token-endpoint)).
Their preflights, and what an actual request gets:

| Provider           | Preflight                                                                                                                                                                                                                                                                       | Actual request                                                                                                                                                                                                                                                                            | Source                                                                                                                                       |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------- |
| node-oidc-provider | 204, for any origin, never checked per Client. Reflects the origin; `Access-Control-Allow-Methods` `POST` at the token endpoint, `GET,POST` at UserInfo; `Access-Control-Allow-Headers` echoes the request's; `Access-Control-Max-Age: 3600`. `Vary: Origin` on every response. | The origin is reflected before the handler runs. Once the Client is known, an origin it does not allow loses the header and gets `invalid_request`. `WWW-Authenticate` is exposed at both endpoints. Whether a token error keeps the header depends on middleware order (**UNVERIFIED**). | `lib/shared/cors.js`, `lib/helpers/initialize_app.js`, `lib/helpers/defaults.js`                                                             |
| Keycloak           | Reflects any origin, unchecked. `Access-Control-Allow-Methods` `POST, OPTIONS` at the token endpoint; `Access-Control-Allow-Headers` a fixed list, with `Authorization` at UserInfo; `Access-Control-Max-Age: 3600`. No `Vary` anywhere.                                        | The origin is reflected only if the Client's Web Origins allow it, checked after client authentication. `WWW-Authenticate` is exposed on UserInfo's Bearer errors. Always sends `Access-Control-Allow-Credentials`.                                                                       | `services/cors/DefaultCors.java`, `server-spi-private/.../cors/Cors.java`, `endpoints/TokenEndpoint.java`, `endpoints/UserInfoEndpoint.java` |

node-oidc-provider's default `clientBasedCORS` refuses the origin `null`.
At UserInfo, or for a Client registered for `none` at any endpoint, it
allows the origins of the Client's redirect URIs, and otherwise none.

## Go

The standard library has no CORS helper: Go 1.27.3's source and API
files have no `Access-Control-*` code. `http.CrossOriginProtection` (Go
1.25) is protection against cross-site request forgery: it sets no
response header and refuses non-safe cross-origin requests, so it must not
wrap an endpoint that serves them. pulsar uses it on the login and consent
pages only. Of third-party packages, `github.com/rs/cors` is the most
imported (9,677 importers on pkg.go.dev, v1.11.1). It decides from the
origin and the request, as middleware does, before the handler has
identified the Client.

## What pulsar does

The answers to #41's questions:

1. **Browser-based public Clients are supported.** Every provider surveyed
   can answer cross-origin requests, RFC 10017 requires the headers of a
   server that supports the architecture, and pulsar already redeems a
   public Client's code with PKCE. The README states that RFC 10017 puts
   the backend-for-frontend architecture first.
2. **The origins of the Client's redirect URIs.** The token endpoint
   allows the origin of one of the redirect URIs of a Client registered
   for `none`, as node-oidc-provider's default does, and Keycloak's Web
   Origin `+`; UserInfo allows that of the Client the access token was
   issued to, whatever its method. The registry's format is unchanged. A
   confidential Client cannot redeem a code from a browser, which cannot
   keep its secret.
3. **The token endpoint, UserInfo and the JWK Set.** The JWK Set is public
   and sends `*`, as discovery does. A preflight is approved for an origin
   that some Client could be allowed at that endpoint, the narrower of the
   two options RFC 10017 describes; an actual request is checked against
   its own Client, and refused before anything changes: a token request
   is sent without a preflight, so a refused one must not redeem a code
   or rotate a refresh token whose response its sender cannot read. The
   authorization endpoint sends no CORS headers, as RFC 9700 §2.6
   requires. `rs/cors` is not used: the check needs the Client, which
   only the handler knows.
4. **The draft is now RFC 10017**, and its §6.3.3.4 is unchanged.
