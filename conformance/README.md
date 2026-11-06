# Conformance

What `make conformance` needs to run the
[OpenID conformance suite](https://gitlab.com/openid/conformance-suite)
against pulsar. The Makefile target says how a run proceeds;
`compose.yaml` says what runs.

| File                     | Contents                                                                                                                            |
| ------------------------ | ----------------------------------------------------------------------------------------------------------------------------------- |
| `compose.yaml`           | pulsar, its PostgreSQL, the suite's prebuilt images at `release-v5.3.4`, and the suite's CI runner                                  |
| `config-op.json`         | The suite's configuration for `oidcc-config-certification-test-plan`                                                                |
| `expected-failures.json` | Conditions the runner is to accept as failures                                                                                      |
| `expected-warnings.json` | Conditions the runner is to accept as warnings                                                                                      |
| `runner/`                | The runner's image: `scripts/run-test-plan.py` from the suite, checksummed, and its hashed dependencies                             |
| `tls/`, `results/`       | Written by each run and ignored by git: pulsar's certificate and key; exported results and the logs of every service but the runner |

The runner fails a run when a condition fails or warns without a matching
entry, and also when an entry matches nothing, so neither file can go
stale. Each entry is an object in the suite's own format, with a `comment`
giving its reason. `make conformance` refuses an entry without one, and
an entry whose `expected-result` is not the one its file is named for:

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
