# Conformance

What `make conformance` needs to run the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
against pulsar. The Makefile target says how a run proceeds;
`compose.yaml` says what runs.

| File                     | Contents                                                                                                                                                          |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `compose.yaml`           | pulsar, its PostgreSQL, the suite's prebuilt images at `release-v5.3.4`, and the suite's CI runner                                                                |
| `config-op.json`         | The suite's configuration for `oidcc-config-certification-test-plan`                                                                                              |
| `config-basic.json`      | The suite's configuration for `oidcc-basic-certification-test-plan`: its Clients' credentials, and the browser automation that signs the End-User in and consents |
| `registry.json`          | pulsar's registry: the three Clients `config-basic.json` names, and the End-User it signs in as                                                                   |
| `expected-failures.json` | Conditions the runner is to accept as failures                                                                                                                    |
| `expected-warnings.json` | Conditions the runner is to accept as warnings                                                                                                                    |
| `expected-skips.json`    | Modules the runner is to accept as skipped                                                                                                                        |
| `runner/`                | The runner's image: `scripts/run-test-plan.py` from the suite, checksummed, and its hashed dependencies                                                           |
| `tls/`, `results/`       | Written by each run and ignored by git: pulsar's certificate and key; exported results and the logs of every service but the runner                               |

The credentials in `config-basic.json` and `registry.json` are for this
stack only and published deliberately (SECURITY.md): the secrets and the
password in plain text in one, as the suite sends them, and as Argon2id
hashes in the other, as pulsar reads them.

`runner/run.sh` runs the Config OP plan and then the Basic OP plan, with
the variants `server_metadata=discovery` and
`client_registration=static_client`. The registered redirect URI is the
one the suite derives from the configuration's `alias`.

The runner fails a run when a condition fails or warns without a matching
entry, when a module is skipped without one, and also when an entry
matches nothing, so no file can go stale. Each entry is an object in the
suite's own format, with a `comment` giving its reason. `make conformance`
refuses an entry without one, a failure or warning entry whose
`expected-result` is not the one its file is named for, and a skip entry
with an `expected-result`; a skip entry names only the module, by
`test-name`, `variant` and `configuration-filename`:

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

Four modules of the Basic OP plan ask for a page to be reviewed rather than
checked by the suite: the login page shown again for `prompt=login` and for
`max_age=1`, and, in two of them, the error page pulsar shows for a
redirect URI the Client did not register. Such a module ends in `REVIEW`,
which the runner accepts.
`config-basic.json` overrides the browser automation for these modules
so that, on reaching that page, it hands the page to the suite, which
records it in the module's log. The suite records the page's HTML, not a
screenshot: its browser automation cannot take one. The exported results in
`results/` keep that HTML in each module's JSON log.
