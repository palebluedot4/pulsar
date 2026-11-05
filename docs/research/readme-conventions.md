# README conventions

Surveyed 2026-11-04 by reading the READMEs and docs of widely adopted
open-source projects (fetched with `gh api repos/<owner>/<repo>/readme`).
Anything not confirmed is marked **UNVERIFIED**.

## Structure

- **Open literally.** Every widely adopted project checked (Kubernetes,
  Istio, etcd, Caddy, Prometheus and others) opens with what it does. A name's
  meaning is carried by the logo and the name itself; where it is explained at
  all, it takes one to three sentences in the docs or at the end of the
  README (Caddy's `## About`), never a leading section.
- **GitHub** ("About READMEs"): what the project does, why it is useful, how
  to start, where to get help, who maintains it; relative links; GitHub
  generates a table of contents from headings.
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes>
- **makeareadme.com:** name, description, badges, visuals, installation,
  usage, support, roadmap, contributing, authors, license, project status;
  move depth into other documents. <https://www.makeareadme.com/>
- **Standard Readme:** title, short description, install, usage,
  contributing, license required; a table of contents beyond 100 lines.
  <https://github.com/RichardLitt/standard-readme>
- **Google documentation guide:** a README is "a short summary" that includes
  status ("deprecated, or not for general release") and links to fuller docs.
  <https://google.github.io/styleguide/docguide/READMEs.html>
- **Length:** comparable Go projects run 100–230 lines; outliers are manuals
  (go-oidc, 1,203 lines) or adopter lists (Hydra, 707).
- **Status:** etcd and Harbor warn that `main` may be unstable; a GitHub
  `> [!WARNING]` alert is the current idiom.
- **Diagrams:** at most one Mermaid diagram; depth goes in `docs/`.

## Presenting OpenID conformance and certification

- `panva/node-oidc-provider` has a `## Certification` section after its spec
  list, showing the official mark linked to the certification page with the
  Foundation's wording: "Filip Skokan has [certified] that oidc-provider
  conforms to the following profiles of the OpenID Connect™ protocol".
  <https://github.com/panva/node-oidc-provider>
- `luikyv/go-oidc` uses the same wording after a supported-specifications
  list; Hydra notes it was certified on a specific version with the reference
  login app.
- `zitadel/oidc` links **public conformance plan results**
  (`certification.openid.net/plan-detail.html?public=true&plan=…`) and keeps a
  spec table marked yes / no / not yet with links to spec sections.
- The mark is granted only after passing, paying and publication by the
  OpenID Foundation, and covers one identified deployment. Before that, the
  accurate claim is "passes the OpenID conformance suite for profiles X",
  linked to public results with dates and commit SHAs.

## Badges

- **Meaningful:** CI status from a live workflow; OpenSSF Scorecard
  (`https://api.scorecard.dev/projects/github.com/{owner}/{repo}/badge`,
  shown by etcd, Prometheus, Envoy, Jaeger, Vitess); conformance results
  produced by CI; Go Reference only if the module exports packages worth
  importing; coverage only if wired to CI.
- **Noise:** Go Report Card (duplicated by golangci-lint; current status
  UNVERIFIED); license (GitHub's sidebar shows it); release, stars, "PRs
  welcome"; any hand-written static "passing" badge.

## Being open about AI-assisted development

- **Ghostty** keeps a separate `AI_POLICY.md`: "Ghostty is written with plenty
  of AI assistance … Our reason for the strict AI policy is not due to an
  anti-AI stance". <https://github.com/ghostty-org/ghostty/blob/main/AI_POLICY.md>
- **simonw/tools** links a colophon listing commit messages and transcripts
  for every tool: evidence rather than claims.
  <https://github.com/simonw/tools>
- **mitsuhiko/sloppy-xml-py** carries a disclaimer that the library is 100% AI
  generated and its quality cannot be vouched for — a framing to avoid when
  the point is that the method produces verifiable quality.
- OpenAI's harness-engineering post describes the repository as the system of
  record; the repository itself is not public (UNVERIFIED).

## Outline derived from the above

1. Title and a one-line tagline, then two literal sentences on what the
   project is.
2. Three or four meaningful badges.
3. Status in one plain sentence: a reference implementation, not for
   production.
4. Evidence at a glance: conformance results with public links, dates and
   commits; requirement-to-test traceability; eval results.
5. Quickstart.
6. What is implemented (spec table, yes / no / not yet) and what is
   deliberately not.
7. How it was built: links into the harness documentation, evals, execution
   plans and transcripts, with measured results and their limits.
8. One architecture diagram.
9. Verification, layout, status.
10. About the name: 80–150 words at the end.
11. License.
