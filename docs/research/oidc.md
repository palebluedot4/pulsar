# OpenID Connect and OAuth: landscape for an OpenID Provider

Surveyed 2026-11-04 against primary sources: the IETF datatracker and RFC
Editor, openid.net, the OpenID conformance suite on GitLab, and
modelcontextprotocol.io. Anything not confirmed is marked **UNVERIFIED**.

## Conformance suite

**Running it locally and in CI** — fully headless.

- Prebuilt Docker stack: `docker-compose-prebuilt.yml` from
  <https://gitlab.com/openid/conformance-suite>; `IMAGE_TAG` pins a release
  (latest `release-v5.3.4`, 2026-10-26). The UI is served on
  `https://localhost.emobix.co.uk:8443/` once a hosts entry maps that name to
  127.0.0.1. <https://gitlab.com/openid/conformance-suite/-/wikis/Developers/Build-&-Run>
- CI driver: `scripts/run-test-plan.py` takes `plan-name[variant=…] config.json`
  pairs, reads `CONFORMANCE_SERVER` / `CONFORMANCE_TOKEN`, and supports
  `--expected-failures-file`, `--expected-skips-file`, `--export-dir`.
- Template to copy: the suite's own CI tests panva's node `oidc-provider` in a
  container (`docker-compose-localtest.yml`,
  `.gitlab-ci/local-provider-oidcc-conformance-config.json`,
  `.gitlab-ci/run-tests.sh`).
- Python tutorial: <https://gitlab.com/openid/conformance-suite-automated-testing-tutorial>

**Login and consent automation:** a `"browser"` array in the plan config.
Each entry has a URL `match` and `tasks` such as `["text","id","username","foo"]`,
`["click","name","submit"]`, `["wait","id","submission_complete",10]`; tasks
can be `"optional"` (useful for consent screens). Selenium runs inside the
suite. <https://gitlab.com/openid/conformance-suite/-/wikis/Design/BrowserControl>
Some modules end in a `REVIEW` state that needs a screenshot for certification.

**Run time:** no official figure (UNVERIFIED). Basic has about 37 modules and
some include deliberate waits (code reuse after 30 seconds, `max_age`), so
expect minutes per plan.

**OP plan names** (from `src/main/java/net/openid/conformance/openid/*TestPlan.java`):

| Profile                   | Plan                                                             |
| ------------------------- | ---------------------------------------------------------------- |
| Basic OP                  | `oidcc-basic-certification-test-plan`                            |
| Config OP                 | `oidcc-config-certification-test-plan` (1 module)                |
| Form Post                 | `oidcc-formpost-{basic,implicit,hybrid}-certification-test-plan` |
| RP-Initiated Logout       | `oidcc-rp-initiated-logout-certification-test-plan`              |
| Back-Channel Logout       | `oidcc-backchannel-rp-initiated-logout-certification-test-plan`  |
| Front-Channel Logout      | `oidcc-frontchannel-rp-initiated-logout-certification-test-plan` |
| Session Management        | `oidcc-session-management-certification-test-plan`               |
| Dynamic OP                | `oidcc-dynamic-certification-test-plan`                          |
| Implicit / Hybrid OP      | `oidcc-implicit-…`, `oidcc-hybrid-certification-test-plan`       |
| FAPI 2.0 Security Profile | `fapi2-security-profile-final-test-plan`                         |
| FAPI 2.0 Message Signing  | `fapi2-message-signing-final-test-plan`                          |

Variant selectors include `server_metadata=discovery|static`,
`client_registration=static_client|dynamic_client`, and for FAPI 2.0
`client_auth_type=mtls|private_key_jwt`.
<https://openid.net/certification/connect_op_testing/>

## Certification

- Fees (<https://openid.net/certification/fees/>, "subject to change"):
  OpenID Connect $700 members / $3,500 non-members per deployment per
  calendar year; FAPI $1,000 / $5,000.
- Open-source fee waiver: available when primary maintainers are not paid by
  an employer to work on the project; judged case by case.
  <https://openid.net/certification/open-source-project-certification-policy/>
- Process: run the plans on the hosted suite
  (<https://www.certification.openid.net/>), export and submit. The OP must be
  publicly reachable for the hosted run. Whether local-run results are
  accepted is UNVERIFIED.
- Certification covers **one identified deployment**, not the software in
  general. The 2026-06 trademark policy reportedly requires the mark to link to
  the certification page and be removed when no longer accurate (UNVERIFIED;
  PDF not extracted).
- Individuals and small projects are on the certified list: Filip Skokan
  (node oidc-provider), Luiky Vasconcelos (go-oidc, Aug 2025), Yuta Hoshina
  (Authrim, Dec 2025), Thomas Meadow (zeroauthy, Oct 2026), Tiago Cardoso
  (rodauth-oauth). <https://openid.net/certification/certified-openid-providers-profiles/>

## Specification status

| Spec                                            | Status (2026-11-04)                                                           | Why it matters                                                                                                                                                                                                 |
| ----------------------------------------------- | ----------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| RFC 9700, OAuth 2.0 Security BCP                | Published Jan 2025 (BCP 240)                                                  | Normative baseline: PKCE, exact redirect matching, no implicit or password grant, rotated or sender-constrained refresh tokens; access tokens SHOULD be sender-constrained; asymmetric client auth RECOMMENDED |
| OAuth 2.1                                       | draft-ietf-oauth-v2-1-17 (2026-10-31); IESG submission targeted Dec 2026      | MCP builds on it                                                                                                                                                                                               |
| RFC 10017, Browser-Based Apps                   | BCP, Aug 2026                                                                 | Ranks BFF above token-mediating backend above browser-only                                                                                                                                                     |
| RFC 9068, JWT access tokens                     | Oct 2021                                                                      | `typ: at+jwt`; local validation at resource servers                                                                                                                                                            |
| RFC 9207, `iss` parameter                       | Mar 2022                                                                      | Mix-up defense; SHOULD in MCP 2026-07-28                                                                                                                                                                       |
| RFC 9126, PAR                                   | Sep 2021                                                                      | Required by FAPI 2.0                                                                                                                                                                                           |
| RFC 9449, DPoP                                  | Sep 2023                                                                      | Sender-constraining without mTLS                                                                                                                                                                               |
| RFC 8705, mTLS                                  | Feb 2020                                                                      | Client auth and certificate-bound tokens                                                                                                                                                                       |
| RFC 8693, Token Exchange                        | Jan 2020                                                                      | On-behalf-of and agent delegation                                                                                                                                                                              |
| RFC 9728, Protected Resource Metadata           | Apr 2025                                                                      | Mandatory for MCP servers                                                                                                                                                                                      |
| RFC 8707, Resource Indicators                   | Feb 2020                                                                      | MCP clients MUST send `resource`                                                                                                                                                                               |
| RFC 8725, JWT BCP                               | Feb 2020; 8725bis-10 at the RFC Editor                                        | Explicit typing, algorithm allow-lists                                                                                                                                                                         |
| Client ID Metadata Document                     | draft-ietf-oauth-client-id-metadata-document-03 (2026-11-02)                  | URL as `client_id`; preferred over DCR by MCP                                                                                                                                                                  |
| Identity Assertion Authorization Grant (ID-JAG) | draft -06 (2026-10-31)                                                        | MCP Enterprise-Managed Authorization; Okta Cross App Access                                                                                                                                                    |
| Transaction Tokens                              | draft -11, Waiting for Write-Up                                               | Workload call-chain context                                                                                                                                                                                    |
| SSF 1.0, CAEP 1.0, RISC 1.0                     | Final, Sep 2025                                                               | Real-time session revocation events                                                                                                                                                                            |
| FAPI 2.0                                        | Security Profile Final Feb 2025; Message Signing Final 2025-09-26             | Conformance plans exist for both                                                                                                                                                                               |
| OIDC logout specs                               | RP-Initiated, Front-Channel, Back-Channel, Session Management: Final Sep 2022 | Front-channel and session management depend on third-party cookies and iframes                                                                                                                                 |
| OIDC Native SSO                                 | Second Implementer's Draft (Oct 2025)                                         | Not final                                                                                                                                                                                                      |
| First-Party Apps                                | draft -04, Waiting for Write-Up                                               | Native login without redirect                                                                                                                                                                                  |

## MCP authorization (spec revision 2026-07-28)

<https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization>

Requirements that land on the authorization server:

- Implement OAuth 2.1; clients MUST use PKCE with S256 and refuse to proceed if
  `code_challenge_methods_supported` is missing.
- Offer RFC 8414 metadata or OIDC Discovery.
- Clients MUST send RFC 8707 `resource` in both authorization and token
  requests; MCP servers MUST validate audience and MUST NOT pass tokens
  through; MCP servers MUST serve RFC 9728 metadata.
- Client registration order: pre-registration, then Client ID Metadata
  Documents (SHOULD; advertise `client_id_metadata_document_supported`), then
  DCR (RFC 7591), which MCP now deprecates. With CIMD the AS MUST check that
  the document's `client_id` equals its URL and SHOULD guard against SSRF.
- Exact redirect matching, refresh-token rotation for public clients,
  short-lived tokens; `iss` (RFC 9207) SHOULD, expected to become MUST.
- Extensions marked stable: Enterprise-Managed Authorization (ID-JAG) and
  OAuth Client Credentials. <https://github.com/modelcontextprotocol/ext-auth>

**Market demand:** Auth0 "Auth for MCP" GA 2026-05-06 (CIMD, token exchange,
resource indicators); WorkOS AuthKit, Descope and Stytch ship MCP
authorization servers. The OpenID Foundation runs an AI Identity Management
community group (whitepaper 2025-10-07).
<https://auth0.com/blog/auth0-auth-for-mcp-servers-generally-available/>,
<https://workos.com/docs/authkit/mcp>

**A second oracle:** the MCP conformance suite has an auth suite for servers
(`--suite auth`), covering protected resource metadata and authorization
server discovery. Exact scenario list UNVERIFIED; list with
`npx @modelcontextprotocol/conformance list --server`.
<https://github.com/modelcontextprotocol/conformance>

## Go OpenID Provider projects

| Project                  | Status                                                                                         |
| ------------------------ | ---------------------------------------------------------------------------------------------- |
| `luikyv/go-oidc`         | MIT OP library; certified Basic, Implicit, Hybrid, Config, Dynamic; README claims FAPI 1.0/2.0 |
| `zitadel/oidc` v3.51.17  | Only the RP is certified; OP certification is a stated goal                                    |
| Ory Hydra v26.2.0        | Certified OP (v1.0.0 listing, 2018)                                                            |
| `ory/fosite`             | Last tag v0.49.0 (Dec 2024)                                                                    |
| Dex v2.46.1              | Not on the certified OP list                                                                   |
| `coreos/go-oidc` v3.21.0 | RP only                                                                                        |

## Relying-party and resource-server practice

**Browser sessions versus JWTs.** Authoritative guidance steers browser
sign-in to cookie sessions rather than JWTs held by JavaScript:

- OWASP JWT cheat sheet: using JWTs for stateless user sessions "is frowned
  upon"; revocation needs a deny list anyway.
  <https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_Cheat_Sheet.html>
- OWASP Session Management: do not store tokens in `localStorage` or
  `sessionStorage`. <https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html>
- RFC 10017 "strongly recommends" a BFF for business and personal-data apps:
  tokens stay server-side; the browser holds a `Secure`, `HttpOnly` cookie
  (`__Host-Http-` prefix, `SameSite=Strict`) with CSRF defense. Server-side
  session stores are "only recommended in small-scale scenarios"; encrypted
  cookie sessions are acceptable because revocation comes from revoking the
  tokens.

**Where JWTs still belong:**

- The `id_token` is consumed once at login to establish the RP's own session;
  it is neither a session token nor an API credential.
- Access tokens to APIs may be JWTs (RFC 9068) or opaque tokens checked by
  introspection (RFC 7662; RFC 9701 for signed responses).
- Resource-server validation (RFC 9068 §4, RFC 8725): require `typ` =
  `at+jwt`; allow-list `alg`, never `none`; check `iss`, `aud` includes this
  resource, `exp`, and scopes; do not follow `jku`/`x5u` blindly.

**Service to service is not "bare JWT preferred."** RFC 9700 says access
tokens SHOULD be sender-constrained (mTLS or DPoP) and audience-restricted,
and RECOMMENDS asymmetric client authentication (mTLS or `private_key_jwt`).
SPIFFE's JWT-SVID spec concedes bearer JWT-SVIDs "are susceptible to replay
attacks"; IETF WIMSE drafts define key-bound workload tokens.
<https://github.com/spiffe/spiffe/blob/main/standards/JWT-SVID.md>

**Other clients and lifecycle:**

- Native apps: RFC 8252 (system browser, PKCE, claimed HTTPS or loopback
  redirects).
- Refresh tokens: public clients need rotation with reuse detection or
  sender-constraining.
- Logout: RP-Initiated plus Back-Channel Logout is the robust pair; SSF/CAEP
  for continuous revocation.

## Implications for scope

- Core profiles worth passing: Basic, Config, Form Post (basic),
  RP-Initiated Logout, Back-Channel Logout.
- Low value or discouraged: Implicit and Hybrid (RFC 9700 and OAuth 2.1
  discourage implicit); Front-Channel Logout and Session Management (fragile
  in modern browsers); Dynamic OP (DCR deprecated by MCP in favor of CIMD).
- `private_key_jwt` follows directly from RFC 9700's recommendation; DPoP is
  the lighter path to sender-constrained tokens and is accepted by both MCP
  deployments and FAPI 2.0.
- FAPI 2.0 Security Profile is achievable for a solo implementer (go-oidc is
  the precedent); Message Signing is the hardest.
- Until certified, describe results as "passes the OpenID conformance suite
  for profiles X" with links to public plan results, dates and commits.
