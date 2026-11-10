# Security policy

pulsar is a reference implementation of an OpenID Provider. It is not
intended for production use, but its security behavior is meant to be
correct, and a report that it is not is welcome.

## Reporting a vulnerability

Report privately through GitHub: **Security → Report a vulnerability** on this
repository. Please do not open a public issue.

Include the affected endpoint or package, the steps to reproduce, and, where
it applies, the specification clause (for example RFC 9700 §2.1) the behavior
violates.

## Conformance test files

The files in `conformance/` run the OpenID conformance suite against a
throwaway pulsar on a Docker network that `make conformance` creates and
removes. Any credential committed there is for that testing only and is
published deliberately: never use one anywhere else. These are the Client
secrets and the End-User password in `config-basic.json` and
`config-logout.json`, and their Argon2id hashes in `registry.json`. The TLS key and
`PULSAR_SECRET` of each run are generated for it and never committed. The
suite runs in its development mode, whose API needs no authentication, so
the stack publishes no port to the host.

## Example credentials

`examples/registry.json` registers an End-User whose password,
`examples-password`, is published in `examples/README.md` and
`examples/examples_test.go`, and the web app example's Client, whose
secret is published in `examples/README.md`, `examples/webapp_test.go` and
`internal/registry/registry_test.go`, with its Argon2id hash in the
registry. They are for the throwaway pulsar that `make examples` runs, and
for that testing only: never use them, or that registry, anywhere else.
The `PULSAR_SECRET` of each run is generated for it and never committed. The stack publishes pulsar's port on the host's loopback
interface alone.

## Supported versions

Only the `main` branch is supported.
