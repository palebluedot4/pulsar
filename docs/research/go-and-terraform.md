# Go and Terraform: dependencies, layout and style

Surveyed 2026-11-04. Versions were checked against `proxy.golang.org`,
importer counts against pkg.go.dev, and adoption by reading the `go.mod` files
of reference projects. Current Go stable is 1.27.3. Anything not confirmed is
marked **UNVERIFIED**.

The selection rule: use the standard library when it covers the need;
otherwise use the single most widely endorsed package, judged by adoption in
major projects, maintenance activity and security history.

## Dependencies

| Need                                     | Choice                                                                                                             | Version              | Evidence                                                                                                                                                                                                                                                                                                                                                           | Runner-up                                                                                                                                             |
| ---------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------- |
| JWS, JWK, JWKS                           | `github.com/go-jose/go-jose/v4`                                                                                    | v4.1.8 (2026-11-02)  | Used by Kubernetes, Dex, Zitadel, Vault, OpenBao, Grafana, and is the only JOSE dependency of `coreos/go-oidc`; ~13 hardening fixes Sep–Oct 2026; past CVEs fixed (CVE-2024-28180, CVE-2025-27144, CVE-2026-34986)                                                                                                                                                 | `lestrrat-go/jwx/v3`: richer API and a JWKS cache, but fewer users and two major lines maintained in parallel. `golang-jwt/jwt/v5` has no JWK support |
| OAuth/OIDC client                        | `golang.org/x/oauth2` + `github.com/coreos/go-oidc/v3`                                                             | v0.37.0; v3.21.0     | 51k and 1.3k importers; pinned by Kubernetes, Dex, Grafana, Caddy; `clientcredentials` subpackage                                                                                                                                                                                                                                                                  | `zitadel/oidc` `rp`                                                                                                                                   |
| RFC 9068 validation at a resource server | go-oidc `NewRemoteKeySet` + `NewVerifier`, plus an explicit `typ: at+jwt` check                                    | —                    | **No Go library implements RFC 9068.** `RemoteKeySet` refetches on unknown `kid` but never checks `typ`                                                                                                                                                                                                                                                            | `MicahParks/keyfunc/v3` (built around golang-jwt)                                                                                                     |
| PostgreSQL driver                        | `github.com/jackc/pgx/v5`                                                                                          | v5.12.0              | 12k importers; Zitadel, Hydra, Vault, Grafana, Authelia, SpiceDB                                                                                                                                                                                                                                                                                                   | `database/sql` + `pgx/stdlib`                                                                                                                         |
| Queries                                  | `sqlc` (generated code imports only pgx)                                                                           | v1.31.1              | De facto type-safe SQL generator; release cadence has slowed since April 2026                                                                                                                                                                                                                                                                                      | plain pgx `CollectRows`                                                                                                                               |
| Migrations                               | `github.com/pressly/goose/v3`                                                                                      | v3.29.0 (2026-10-11) | Actively maintained; Grafana, OpenFGA; embeds via `embed.FS`, advisory locking, Go or SQL migrations                                                                                                                                                                                                                                                               | `golang-migrate/migrate/v4` has ~3× the importers but 500+ open issues and PRs                                                                        |
| Routing                                  | stdlib `net/http.ServeMux` (method and wildcard patterns, Go 1.22+)                                                | —                    | Covers the need. No major Go OP uses gin: Hydra uses httprouter, Dex gorilla/mux, Zitadel chi                                                                                                                                                                                                                                                                      | `go-chi/chi/v5`                                                                                                                                       |
| CSRF                                     | stdlib `http.CrossOriginProtection` (Go 1.25)                                                                      | —                    | Fetch Metadata with Origin fallback; the Go project's remediation for gorilla/csrf CVE-2025-47909. Apply only to login/consent UI and BFF routes: protocol traffic (`form_post`, logout) is legitimately cross-site                                                                                                                                                | `filippo.io/csrf`                                                                                                                                     |
| Sessions                                 | `github.com/alexedwards/scs/v2` + `pgxstore`                                                                       | v2.9.0               | Server-side store; OWASP advises a framework session manager over a home-made one                                                                                                                                                                                                                                                                                  | `gorilla/sessions` (no release since Aug 2024, cookie-store oriented)                                                                                 |
| Password hashing                         | `golang.org/x/crypto/argon2` (`IDKey`)                                                                             | x/crypto v0.58.0     | OWASP: Argon2id, ≥19 MiB, 2 iterations, parallelism 1; bcrypt is legacy-only                                                                                                                                                                                                                                                                                       | `x/crypto/bcrypt`                                                                                                                                     |
| Logging                                  | stdlib `log/slog`                                                                                                  | —                    | Bridge to OTel with `otelslog`                                                                                                                                                                                                                                                                                                                                     | —                                                                                                                                                     |
| Config                                   | stdlib `os.LookupEnv` + `flag`                                                                                     | —                    | Covers environment and flags                                                                                                                                                                                                                                                                                                                                       | `caarlos0/env/v11`                                                                                                                                    |
| Testing                                  | stdlib `testing` + `github.com/google/go-cmp`                                                                      | v0.7.0               | Go Test Comments and Google's guide both reject assertion libraries; `testing/synctest` for clocks                                                                                                                                                                                                                                                                 | `testify` (more raw adoption)                                                                                                                         |
| Fuzzing                                  | stdlib `go test -fuzz`                                                                                             | —                    | —                                                                                                                                                                                                                                                                                                                                                                  | —                                                                                                                                                     |
| Mutation testing                         | none in the gate; `go-gremlins/gremlins` for one-off measurement                                                   | v0.6.0               | No Go standard exists; gremlins is early-stage                                                                                                                                                                                                                                                                                                                     | `go-mutesting`                                                                                                                                        |
| Lint                                     | golangci-lint v2, installed as a binary                                                                            | v2.15.0              | De facto standard; its docs advise against installing it via `go tool`                                                                                                                                                                                                                                                                                             | —                                                                                                                                                     |
| Vulnerabilities                          | `govulncheck`                                                                                                      | v1.9.0               | Official Go tool                                                                                                                                                                                                                                                                                                                                                   | —                                                                                                                                                     |
| Telemetry                                | `go.opentelemetry.io/otel`                                                                                         | v1.47.0              | Traces, metrics, logs stable in the SDK; `otelhttp`, `otelslog` and OTLP log exporters still pre-1.0                                                                                                                                                                                                                                                               | —                                                                                                                                                     |
| MCP server                               | `github.com/modelcontextprotocol/go-sdk`                                                                           | v1.8.0               | Official SDK; supports spec 2026-07-28 from v1.7.0; `auth.RequireBearerToken`, `ProtectedResourceMetadataHandler`, `oauthex.MatchesResource` (RFC 8707); token verification is supplied by the caller                                                                                                                                                              | `mark3labs/mcp-go`                                                                                                                                    |
| Tool pinning                             | `tool` directives in a separate module, `tools/go.mod`, run with `go tool -modfile=tools/go.mod`                   | Go 1.24+             | Keeps tool dependencies out of the main module graph; a real module directory is one Dependabot can update, which a bare `go.tool.mod` beside `go.mod` is not                                                                                                                                                                                                      | tools in main `go.mod`                                                                                                                                |
| Markdown, YAML, JSON formatting          | Prettier                                                                                                           | v3.9.10              | The most widely adopted formatter for these formats (~52k stars); Grafana uses it beside Go. Its default `proseWrap: preserve` keeps hand-wrapped prose                                                                                                                                                                                                            | dprint, mdformat (far smaller adoption)                                                                                                               |
| Markdown linting                         | `markdownlint-cli2`, with the rules markdownlint's `style/prettier` disables turned off                            | v0.24.0              | The same engine as the markdownlint editor extension; OpenTelemetry Go lints with it. A linter, not a formatter: it complements Prettier                                                                                                                                                                                                                           | —                                                                                                                                                     |
| Node package manager                     | pnpm, pinned through `packageManager`                                                                              | v12.16.1             | Since v11, supply-chain protection is on by default: new releases are not resolved for a day, dependency build scripts are refused, and exotic transitive sources are blocked. Dependabot's support for v11 and later lockfiles is contested (changelog says yes, support table says v7–v10); on 2026-11-05 it failed to update this repository's pnpm 12 lockfile | npm (none of those defaults)                                                                                                                          |
| Release-binary installation              | Download the pinned release into `./bin` under a versioned name, verifying the published checksum where one exists | —                    | Upstream's supported path for golangci-lint; no global install, and a version bump is a reinstall                                                                                                                                                                                                                                                                  | Global package managers (unpinned)                                                                                                                    |

## Entrypoint and layout

What large Go projects do, read from source:

| Project                                               | Entrypoint                                                                                                 |
| ----------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| Kubernetes                                            | `cmd/kube-apiserver/apiserver.go` is three lines; logic in the importable `cmd/kube-apiserver/app` package |
| moby, Vault, etcd, CockroachDB, Caddy, Hydra, Zitadel | Thin `main` delegating to a library package                                                                |
| Dex                                                   | `cmd/dex` is a nine-file `package main`; `serve.go` is 958 lines                                           |
| Prometheus                                            | `cmd/prometheus/main.go` is 2,394 lines                                                                    |

Thin mains appear where several binaries or a command tree reuse the logic.
Single-server projects often keep wiring in `package main`.

Guidance:

- go.dev "Server project" layout: server logic in `internal/`; commands in
  `cmd/` when the repository has other non-Go directories.
  <https://go.dev/doc/modules/layout>
- `golang-standards/project-layout` is not a Go standard; Russ Cox, issue
  #117: "this is not a standard Go project layout". Do not use `pkg/`.
- Mat Ryer, "How I write HTTP services in Go after 13 years" (2024): `main`
  only calls `run(ctx, args, getenv, stdin, stdout, stderr) error`; signal
  handling moves into `run`; `NewServer(deps…) http.Handler` with a single
  `routes.go`; tests drive `run` end to end; injecting `getenv` keeps
  `t.Parallel()` usable where `t.Setenv` would forbid it.
- Google Best Practices, "Program initialization": initialization errors
  propagate to `main`, which exits with an actionable message; no `log.Fatal`.

Conclusion: for a single-binary server the endorsed shape is `cmd/<name>/main.go`
holding `main` and `run` in `package main`, with domain packages under
`internal/`. A Kubernetes-style `app` package is justified only when another
program imports the command; an `internal/app` package has no authority behind
it.

**Splitting `internal/`:** by domain, not by layer. Dex splits into `server/`,
`storage/`, `connector/`; Hydra into `oauth2/`, `jwk/`, `consent/`, `client/`.
Google warns against `util`/`common` packages and favors fewer cohesive
packages over many tiny ones.

**Consumer examples as a separate module:** a nested `go.mod` keeps example
dependencies out of the main module graph and its vulnerability scans, and
with no `require` on the main module the examples can only reach the server
over the wire, as real relying parties do.

**Version stamping:** `runtime/debug.ReadBuildInfo` carries the VCS version
since Go 1.24; no ldflags needed.

## Style authorities

In the order the documents themselves establish:

1. The language specification, `gofmt`, `go vet`, `go fix`.
2. Effective Go — Google's guide treats it as "a common baseline for Go code
   across the entire Go community".
3. Go Code Review Comments — "a supplement to Effective Go".
   <https://go.dev/wiki/CodeReviewComments>
4. Go Test Comments — "a supplement to Go Code Review Comments … targeted
   specifically to test code".
5. Go doc comments, <https://go.dev/doc/comment>, and the package names post.
6. Google Go Style Guide: the Guide is normative and canonical; Decisions is
   normative; Best Practices is neither.
   <https://google.github.io/styleguide/go/>

Settled conventions:

- **Errors:** wrap with `%w` at the end; lowercase strings without
  punctuation; sentinels for identity, types for data; `errors.AsType[T]`
  (Go 1.26). OAuth protocol endpoints use RFC 6749 §5.2
  `{"error","error_description"}`, not RFC 9457.
- **Tests:** table-driven with `t.Run`; failures as `Func(args) = got, want`;
  prefer `t.Error` over `t.Fatal`; `cmp.Diff`, never `reflect.DeepEqual`;
  `b.Loop()`; native fuzzing; real transports and a real PostgreSQL.
- **Time and randomness in tests:** `testing/synctest` for clocks. Since
  Go 1.26 crypto key generation ignores a caller-supplied `io.Reader`; use
  `testing/cryptotest.SetGlobalRandom`.
- **Naming:** short receivers, initialisms (`ID`, `URL`, `HTTP`), no stutter,
  no `util`.
- **Context:** first parameter, never stored in a struct.
- **Logging:** `log/slog` with `*Context` methods; vet checks key-value pairs.
- **Modernization:** since Go 1.26 `go fix` hosts the modernizers (`any`,
  `minmax`, `rangeint`, `slicescontains`, `stringscut`, `bloop`, …); Go 1.27
  adds more and makes `go mod tidy` enforce two require blocks. Run
  `go fix ./...` after each toolchain upgrade.
- **Spelling:** the Go project writes American English. Measured in `src/`,
  American against British spellings: behavior 434 to 20; initialize 141 to
  0; canceled 127 to 8. The public API is American (`context.Canceled`,
  `image/color`), and so are the OAuth wire identifiers
  (`authorization_endpoint`). No written policy found (UNVERIFIED absence).
- **Commit messages:** the Go project uses `pkg/path: summary`; Conventional
  Commits is the more widespread convention across the wider ecosystem.
  Either is defensible if chosen deliberately.

## Terraform

From <https://developer.hashicorp.com/terraform/language/style> and the
standard module structure:

- **Files:** `terraform.tf` (a single `terraform` block with `required_version`
  and `required_providers`; the community also uses `versions.tf`),
  `providers.tf`, `backend.tf`, `main.tf`, `variables.tf` and `outputs.tf`
  (alphabetical), `locals.tf`; split `main.tf` by concern as it grows.
- **Structure:** nested modules under `modules/` only when something is reused;
  usage samples under `examples/`.
- **Naming:** descriptive snake_case nouns that do not repeat the resource
  type; `#` comments only.
- **Blocks:** `count`/`for_each` first, `lifecycle` and `depends_on` last;
  every variable has `type` and `description`, every output `description`;
  secrets `sensitive = true` (still plain text in state).
- **Pinning:** pin providers and a minimum `required_version`; pin registry
  modules; commit `.terraform.lock.hcl`; ignore state and `.terraform/`.
  Current: Terraform v1.17.1, AWS provider v6.71.0.
- **Tooling:** `terraform fmt -recursive`, `terraform validate`, TFLint,
  `terraform test`; tfsec is deprecated in favor of Trivy (Checkov is an
  alternative). terraform-aws-modules enforce TFLint rules such as
  `naming_convention`, `documented_variables`, `typed_variables`,
  `module_pinned_source`, `standard_module_structure`.
- **Shape:** start with a single root module; split into separate root
  modules (network, database, compute) only when the stack grows.

## Repository supply-chain hygiene

OpenSSF Scorecard checks these, and they matter more for an identity
provider: dependency update automation (Dependabot for Go modules, GitHub
Actions and Terraform), GitHub Actions pinned by commit SHA, read-only default
workflow `permissions:`, branch protection with CODEOWNERS, a `SECURITY.md`,
and a published Scorecard result.
<https://github.com/ossf/scorecard>
