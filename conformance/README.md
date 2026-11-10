# Conformance

What `make conformance` needs to run the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
against pulsar. The Makefile target says how a run proceeds;
`compose.yaml` says what runs.

| File                     | Contents                                                                                                                                                                                                      |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `compose.yaml`           | pulsar, its PostgreSQL, the suite's prebuilt images at `release-v5.3.4`, and the suite's CI runner                                                                                                            |
| `config-op.json`         | The suite's configuration for `oidcc-config-certification-test-plan`                                                                                                                                          |
| `config-basic.json`      | The suite's configuration for `oidcc-basic-certification-test-plan`: its Clients' credentials, and the browser automation that signs the End-User in and consents                                             |
| `config-formpost.json`   | The same for `oidcc-formpost-basic-certification-test-plan`, whose browser automation also passes pulsar's form-post page                                                                                     |
| `config-logout.json`     | The suite's configuration for `oidcc-rp-initiated-logout-certification-test-plan`: its Client's credentials, and the browser automation that signs in and confirms logout                                     |
| `registry.json`          | pulsar's registry: the three Clients `config-basic.json` and `config-formpost.json` name, the one of them `config-logout.json` names with its post-logout redirect URI, and the End-User all three sign in as |
| `expected-failures.json` | Conditions the runner is to accept as failures                                                                                                                                                                |
| `expected-warnings.json` | Conditions the runner is to accept as warnings                                                                                                                                                                |
| `expected-skips.json`    | Modules the runner is to accept as skipped                                                                                                                                                                    |
| `runner/`                | The runner's image: `scripts/run-test-plan.py` from the suite, checksummed, and its hashed dependencies                                                                                                       |
| `tls/`, `results/`       | Written by each run and ignored by git: pulsar's certificate and key; exported results and the logs of every service but the runner                                                                           |

The credentials in `config-basic.json`, `config-formpost.json`,
`config-logout.json` and `registry.json` are for this stack only and
published deliberately (SECURITY.md): the secrets and the password in plain
text in one, as the suite sends them, and as Argon2id hashes in the other,
as pulsar reads them. `conformance-client`'s secret was made by
`pulsar client-secret`. The logout plan's
`oidcc-rp-initiated-logout-bad-id-token-hint` signs an HS256 hint with it,
and the suite refuses a secret shorter than 32 bytes for that
(`GenerateJWKsFromClientSecret` at `release-v5.3.4`).

`runner/run.sh` runs the Config OP plan, then the Basic OP plan, then the
Form Post Basic plan, the last two with the variants
`server_metadata=discovery` and `client_registration=static_client`, and
then the RP-Initiated Logout plan, with `response_type=code` and
`client_registration=static_client`; that plan sets its other variants
itself. The Form Post Basic plan is the Basic OP plan's modules with
`response_mode=form_post` on every authorization request; it checks that
every response, errors too, arrives at the callback by POST. Its
configuration is `config-basic.json` but for the browser automation:
pulsar's form-post page is at its authorization endpoint, which the
consent task matches, so that task's click is optional. The suite's
browser automation is HtmlUnit with JavaScript on
(`frontchannel/BrowserControl.java` at `release-v5.3.4`), so the page's
script submits the form; a further task only waits until the browser
reaches the callback, and never clicks the page's button, which would
submit it a second time. The registered redirect URI and post-logout
redirect URI are the ones the suite derives from the configurations'
shared `alias` and its own `BASE_URL` in `compose.yaml`; a change to either
changes the `redirect_uris` and `post_logout_redirect_uris` in
`registry.json`, and the URLs that `config-basic.json`,
`config-formpost.json` and `config-logout.json` match.

The runner fails a run when a condition fails or warns without a matching
entry, when a module is skipped without one, and also when an entry
matches nothing, so no file can go stale. Each entry is an object in the
suite's own format, with a `comment` giving its reason. `make conformance`
refuses an entry without one, a failure or warning entry whose
`expected-result` is not the one its file is named for, and a skip entry
with any field but `test-name`, `variant`, `configuration-filename` and
`comment`, since it names a whole module. The runner also counts a listed
module that ends `FAILED` as the skip expected, though any condition that
failed in it is still reported unless listed. The Basic OP and Form Post
Basic plans run the same modules, so an entry for both names the
configuration `*`, which the Config OP plan, running none of those
modules, never matches; such an entry goes stale only once neither plan
needs it. An entry looks like this:

```json
{
  "test-name": "oidcc-discovery-endpoint-verification",
  "variant": "*",
  "configuration-filename": "*config-op.json",
  "current-block": "",
  "condition": "CheckForUnexpectedParametersInServerMetadata",
  "expected-result": "warning",
  "comment": "Why this result is correct for pulsar, citing the clause."
}
```

Run with `--verbose`, as `runner/run.sh` does, the runner prints such a
template for each unexpected result.

## Pages a person would review

Four modules of the Basic OP plan, and the same four of the Form Post Basic
plan, ask for a page to be reviewed rather than checked by the suite. `oidcc-prompt-login` and `oidcc-max-age-1` review
the login page shown again for `prompt=login` and for `max_age=1`;
`oidcc-ensure-registered-redirect-uri` and
`oidcc-ensure-request-object-with-redirect-uri` review the error page
pulsar shows for a redirect URI the Client did not register. Such a module
ends in `REVIEW`, which the runner accepts.
The browser automation in `config-basic.json` and `config-formpost.json`
hands that page to the
suite, which records it in the module's log: any login page does so for a
module waiting for one, and an override does so for each of the two
modules that expect the error page. A module whose page never comes never
finishes, and the run fails. The suite records the page's HTML, not a
screenshot: its browser automation cannot take one. The exported results in
`results/` keep that HTML in each module's JSON log.

Eight modules of the RP-Initiated Logout plan end in `REVIEW` too. Each
sends the End-User to the logout endpoint with a request after which
pulsar must not redirect, fails if pulsar does, and waits for the page
pulsar shows instead, which an override in `config-logout.json` hands it:

| Module                                                              | Request                                                       | Page recorded                                      | Why                                                                                                                               |
| ------------------------------------------------------------------- | ------------------------------------------------------------- | -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| `oidcc-rp-initiated-logout-bad-post-logout-redirect-uri`            | A post-logout redirect URI the Client did not register        | The confirmation page                              | No redirect to a URI the Client did not register (REQ-LOGOUT-9); pulsar asks the End-User to confirm in every case (REQ-LOGOUT-8) |
| `oidcc-rp-initiated-logout-query-added-to-post-logout-redirect-uri` | The registered URI with `?foo=bar` added                      | The confirmation page                              | The URI must match exactly (REQ-LOGOUT-9)                                                                                         |
| `oidcc-rp-initiated-logout-no-id-token-hint`                        | A registered URI with neither a hint nor a `client_id`        | The confirmation page                              | Without either, no Client is identified, so no redirect (REQ-LOGOUT-9)                                                            |
| `oidcc-rp-initiated-logout-modified-id-token-hint`                  | A hint re-headed `alg: none`, its signature dropped           | The error page                                     | A hint pulsar did not sign is refused, with no logout (REQ-LOGOUT-2, REQ-LOGOUT-12)                                               |
| `oidcc-rp-initiated-logout-bad-id-token-hint`                       | A hint the suite signed HS256, keyed with the Client's secret | The error page                                     | The same: pulsar's ID tokens are RS256, signed with one of its own keys                                                           |
| `oidcc-rp-initiated-logout-no-post-logout-redirect-uri`             | A hint and `state` only                                       | The signed-out page, after the automation confirms | With no URI there is nowhere to redirect; the End-User is told they are signed out (REQ-LOGOUT-8)                                 |
| `oidcc-rp-initiated-logout-only-state`                              | `state` only                                                  | The signed-out page, after the automation confirms | The same, without a hint                                                                                                          |
| `oidcc-rp-initiated-logout-no-params`                               | Nothing                                                       | The signed-out page, after the automation confirms | The same, with no parameters at all (REQ-LOGOUT-11)                                                                               |

The plan's other modules, `oidcc-rp-initiated-logout-discovery-endpoint-verification`,
`oidcc-rp-initiated-logout` and `oidcc-rp-initiated-logout-no-state`, are
checked by the suite: the last two follow the redirect back, check `state`,
and then check that `prompt=none` fails. No entry in the expected-results
files names the logout plan. The plan has not yet run against pulsar: it
was wired up without Docker, by analogy with the Basic OP plan, so the
first run may need its overrides or expected results adjusted.
