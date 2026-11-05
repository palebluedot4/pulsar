# pulsar

An OpenID Connect Provider in Go, built by AI agents under a harness that has
to prove it helps. The provider is the artifact; the method is the subject.
It is a reference implementation, not for production use. So far it serves
a liveness check; the OpenID endpoints are next.

## Running it

```sh
go run ./cmd/pulsar            # listens on :8080; PULSAR_ADDR overrides
curl -i localhost:8080/livez
```

## Verifying it

With Go, Node.js, pnpm, jq and Claude Code installed:

```sh
make setup     # once per clone: pinned tools, git hooks, Claude Code plugin
make verify    # what CI runs
```

## How it is built

[AGENTS.md](AGENTS.md) is the map agents work from.
[docs/harness.md](docs/harness.md) lists every control on them and the
evidence for each, and [docs/research/](docs/research/) holds the dated
surveys the decisions rest on.

## About the name

A pulsar's period is its own, and anyone with a radio telescope can check it;
an ID token should be as easy to verify. The
[Pioneer plaques](https://en.wikipedia.org/wiki/Pioneer_plaque) and
Voyager's Golden Record place the Sun among 14 pulsars, and Voyager 1, which
carries that map, took the Pale Blue Dot photograph.

## License

[Apache 2.0](LICENSE).
