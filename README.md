# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness that has
to prove it helps. The provider is the artifact; the method is the subject.
It is a reference implementation, not for production use.

## Running it

```sh
go run ./cmd/pulsar            # listens on :8080; PULSAR_ADDR overrides
curl -i localhost:8080/livez
```

## Verifying it

With Go, Node.js, pnpm, jq and Claude Code installed:

```sh
make setup     # once per clone: pinned tools, git hooks, Claude Code plugins
make verify    # what CI runs
```

## How it is built

[AGENTS.md](AGENTS.md) is the map agents work from.
[docs/harness.md](docs/harness.md) lists every control on them and the
evidence for each, and [docs/research/](docs/research/) holds the dated
surveys the decisions rest on.

## License

[Apache 2.0](LICENSE).
