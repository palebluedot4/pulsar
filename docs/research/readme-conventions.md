# README conventions

Surveyed 2026-11-04 and extended 2026-11-11 by reading the READMEs and docs
of widely adopted open-source projects (fetched with
`gh api repos/<owner>/<repo>/readme`). Anything not confirmed is marked
**UNVERIFIED**.

The extension asks what the maintainer needs to restructure `README.md`,
whose opening is one paragraph of about 100 lines listing behaviors, error
codes and lifetimes, with the run instructions after operational detail. It
covers: the structure and length of twelve READMEs; how OpenID and OAuth
projects present the specifications they support; how projects state that
development is paused, finished or in maintenance; where configuration
reference goes; what documentation style guides say that bears on a README;
and anything new on reporting conformance. READMEs were read on 2026-11-11
at these default-branch commits:

- `kubernetes/kubernetes` `7898e97f1724f72869caa6b354eda92845a6b7f8`
- `etcd-io/etcd` `6974f522338b7dc67575080f07285e5b4348d47d`
- `prometheus/prometheus` `49c815a0ea46c7a6a6b723e4b634c4bf36f7022c`
- `caddyserver/caddy` `f458aa0081f55445b09fae9799d40ed98ed4b3b7`
- `golang/go` `26a3c1f26e117eba697ef4ad87dd487aea46e58d`
- `hashicorp/terraform` `79f788eaaf74d9fb8239d27992f59eef844bf787`
- `dexidp/dex` `4a01df59c0d63bad0e904939db51e467f82638b4`
- `ory/hydra` `4174065ffb052799890f7480f5360a877a67ffc1`
- `zitadel/oidc` `93942e17c6dd6e715232e5f7ffae8467c256b53d`
- `panva/node-oidc-provider` `3ed87bef95d0f02b72917b9eb7d17ef5c3b2313b`
- `luikyv/go-oidc` `6aeac93f370044ca9a59a556b9230cd10bd96868`
- `keycloak/keycloak` `d052236442de082d459a404ce453713b36549594`

Style guides were read from their sources where those are public: GitHub's
docs from `github/docs`, Google's docguide from `google/styleguide`
(`gh-pages`), the Kubernetes style guide from `kubernetes/website`, and
Diátaxis from `evildmp/diataxis-documentation-framework`. The Google
developer documentation style guide was read at developers.google.com.

## Structure

- **Open literally.** Every widely adopted project checked (Kubernetes,
  Istio, etcd, Caddy, Prometheus and others) opens with what it does. A name's
  meaning is carried by the logo and the name itself; where it is explained at
  all, it takes one to three sentences in the docs or at the end of the
  README (Caddy's `## About`), never a leading section.
- **GitHub** ("About READMEs"): what the project does, why it is useful, how
  to start, where to get help, who maintains it; relative links; GitHub
  generates a table of contents from headings. "A README should only contain
  information necessary for developers to get started using and contributing
  to your project. Longer documentation is best suited for wikis."
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
- **Length:** of the twelve READMEs below, ten run 42–231 lines; the
  outliers are a manual (go-oidc, 1,203 lines) and an adopter list (Hydra,
  707, about 350 of them adopters).
- **Status:** etcd and Harbor warn that `main` may be unstable; a GitHub
  `> [!WARNING]` alert is the current idiom.
- **Diagrams:** at most one Mermaid diagram; depth goes in `docs/`.

## Twelve READMEs compared

"Opening" is the prose before the first `##` heading, leaving out logos and
badges. "Quickstart" is the section where a reader first gets something
running, and the line of its heading.

| Project            | Lines | Opening                                                                                                 | Quickstart                                                       | Depth lives in                                                                   |
| ------------------ | ----- | ------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------------------------------- |
| Kubernetes         | 100   | Six sentences in three paragraphs: what it is, its lineage (Borg), its host (CNCF)                      | None; "See our documentation on kubernetes.io"; build at line 35 | kubernetes.io; the `community` repository for contributors                       |
| etcd               | 204   | A note that `main` may be broken, one sentence, four bulleted qualities, three short paragraphs         | "Getting started", line 61, after Documentation and Maintainers  | etcd.io/docs; Go package docs                                                    |
| Prometheus         | 231   | A line sending readers to prometheus.io, one sentence, eight bulleted distinguishing features           | "Install", line 40, with a one-line `docker run` at line 60      | prometheus.io                                                                    |
| Caddy              | 225   | A tagline and one sentence, then a menu (table of contents) and a bulleted feature list linking to docs | "Install", line 98; "Quick start", line 164, links out           | caddyserver.com/docs; the name's story in `## About` at the end                  |
| Go                 | 42    | One sentence                                                                                            | None; links to go.dev/dl and the install guide                   | go.dev                                                                           |
| Terraform          | 48    | Five links, two sentences, four bulleted features                                                       | None; links to tutorials                                         | developer.hashicorp.com                                                          |
| Dex                | 124   | Two sentences                                                                                           | None; "Documentation" links to dexidp.io                         | dexidp.io; the README keeps an ID token example and a connector table            |
| Ory Hydra          | 707   | Two sentences, then a generated table of contents                                                       | "Quickstart", line 199, after certification and deployment       | ory.com/docs/hydra; `DEVELOP.md`                                                 |
| zitadel/oidc       | 224   | Three sentences and a `> [!NOTE]` alert                                                                 | "How To Use It", line 49: run the example OP and RP              | The README, `example/` and Go package docs                                       |
| node-oidc-provider | 177   | One sentence, then a table of contents                                                                  | A code sample under "Documentation & Configuration", line 92     | `docs/README.md` (5,246 lines) in the repository                                 |
| go-oidc            | 1,203 | One sentence: "A configurable OpenID Connect Provider for Go."                                          | "Get Started", line 57, after specifications and certification   | The README itself: a table of contents and 31 sections, one per grant or feature |
| Keycloak           | 87    | Two sentences under the heading "Open Source Identity and Access Management"                            | "Getting started", line 37: two commands                         | keycloak.org; `docs/building.md` and `docs/tests.md` for contributors            |

- **Openings are short.** None of the twelve opens with more than six
  sentences of prose; the longest, Kubernetes, is three paragraphs. Where
  there is more to say up front, it is a bulleted list of features (etcd,
  Prometheus, Terraform, Caddy), not a longer paragraph.
- **Order.** What it is; how to get it or run it; where the documentation
  is; how to get help, contribute and report a vulnerability; license. The
  OpenID projects put their specification list and certification before the
  quickstart (node-oidc-provider, go-oidc, Hydra).
- **Depth lives elsewhere.** Ten of the twelve keep behavior and
  configuration out of the README, on a website or in a file under `docs/`;
  only go-oidc and, for its example server, zitadel/oidc keep it in the
  README.

## Presenting supported specifications

- **node-oidc-provider:** a bulleted list headed "Implemented specs &
  features", each item the specification's short name (`RFC7636`) linked to
  its text, marked "(not exhaustive)", with a note that "not all features
  are enabled by default". Experimental features are a separate list that
  names each draft's version.
  <https://github.com/panva/node-oidc-provider#implemented-specs--features>
- **go-oidc:** a bulleted list, "Supported Specifications", each linked to
  its text, with drafts under their own `### Drafts` heading.
  <https://github.com/luikyv/go-oidc#supported-specifications>
- **zitadel/oidc:** a table with one row per feature and columns "Relying
  party", "OpenID Provider" and "Specification", the last linking to the
  section (for example, "OpenID Connect Core 1.0, Section 3.1"). Cells read
  `yes`, `no` or `not yet`; one `no` carries a footnote linking to the issue
  that explains it. <https://github.com/zitadel/oidc#features>
- **Hydra:** two bulleted lists, IETF and OpenID Foundation specifications,
  linked to their texts, with no statement of what is not supported.
  <https://github.com/ory/hydra#oauth2-and-openid-connect-open-standards>
- **Dex:** its connectors in a table with a `status` column (stable, beta,
  alpha), definitions of each status beneath, and a "notes" column that
  carries a warning ("Unmaintained and likely vulnerable to auth bypasses")
  linking to a discussion. <https://github.com/dexidp/dex#connectors>
- So: a list when the only fact is "implemented"; a table when each row
  carries more than one fact (role, status, section). Only zitadel/oidc and
  Dex state in the README what is not supported, each with a reason or a
  link to one. Google's guide agrees: when "each item is three or more
  pieces of related data", "Use a table."
  <https://developers.google.com/style/tables>

## Stating status

- **GitHub alerts** (`> [!NOTE]`, `[!TIP]`, `[!IMPORTANT]`, `[!WARNING]`,
  `[!CAUTION]`): "Use alerts only when they are crucial for user success and
  limit them to one or two per article to prevent overloading the reader."
  `[!IMPORTANT]` is "Key information users need to know to achieve their
  goal"; `[!WARNING]`, "Urgent info that needs immediate user attention to
  avoid problems."
  <https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax#alerts>
- **Archiving** makes a repository read-only for all users, issues and pull
  requests included, and can be undone. GitHub recommends that you "update
  the README file and description, before you archive a repository."
  <https://docs.github.com/en/repositories/archiving-a-github-repository/archiving-repositories>
- **repostatus.org** defines eight statuses as badges for a README. The two
  nearest to pulsar: "Inactive – The project has reached a stable, usable
  state but is no longer being actively developed; support/maintenance will
  be provided as time allows", and "Concept – … the repository is only
  intended to be a limited example, demo, or proof-of-concept." None of the
  twelve READMEs above shows one. <https://www.repostatus.org/>
- **Google's docguide** lists, among what a README should include or point
  to, "Status of whether this package or library is deprecated, or not for
  general release, etc."
  <https://google.github.io/styleguide/docguide/READMEs.html>
- **Notices in well-known repositories,** each in the first lines:
  - Logrus (not archived): "**Logrus is in maintenance mode.** The project
    focuses on security, bug fixes, and performance improvements. New
    features are not planned", then why.
    <https://github.com/sirupsen/logrus>
  - Moment.js: "Moment.js is a legacy project, now in **maintenance mode**.
    New features are not being accepted", linking a status update.
    <https://github.com/moment/moment>
  - golang/lint (archived): "**NOTE:** Golint is deprecated and frozen",
    linking the issue that decided it, then what to use instead.
    <https://github.com/golang/lint>
  - golang/mock (archived): "**Update, June 2023**: _This repo and tool are
    no longer maintained._" A dated notice. <https://github.com/golang/mock>
  - IdentityServer4 (archived): "This project is not maintained anymore and
    is now archived", then that it has known vulnerabilities and where the
    successor is. <https://github.com/DuendeArchive/IdentityServer4>
  - zitadel/oidc: a `> [!NOTE]` alert, "We currently have limited
    availability for feature reviews", linking a discussion.
    <https://github.com/zitadel/oidc>
  - Hydra's login and consent app opens "This is a reference implementation
    for the User Login and Consent flow of Ory OAuth2 service (Hydra)".
    <https://github.com/ory/hydra-login-consent-node>
- So: the status comes first, in one or two sentences, says what will and
  will not change (security fixes, features, reviews), and links to the
  record of the decision. Dated notices (golang/mock) and links do not go
  stale the way "currently" does; the Kubernetes guide says to "Avoid words
  like 'currently' and 'new.'"
  <https://kubernetes.io/docs/contribute/style/style-guide/#avoid-statements-that-will-soon-be-out-of-date>

## Where configuration reference goes

- **On the project's website:** etcd ("every flag has a corresponding
  environment variable … prefixed with `ETCD_`"),
  <https://etcd.io/docs/latest/op-guide/configuration/>; Prometheus,
  <https://prometheus.io/docs/prometheus/latest/configuration/configuration/>;
  Terraform's environment variables,
  <https://developer.hashicorp.com/terraform/cli/config/environment-variables>;
  Keycloak's options, each with its `KC_` variable,
  <https://www.keycloak.org/server/all-config>; Dex,
  <https://dexidp.io/docs/configuration/>; Hydra, linked from the README's
  "Documentation" as "Configuration reference",
  <https://www.ory.com/docs/hydra/reference/configuration>.
- **In a file in the repository:** node-oidc-provider's `docs/README.md`,
  whose "Configuration options" section runs from line 585 to 5,102.
  <https://github.com/panva/node-oidc-provider/blob/main/docs/README.md>
- **In the README:** zitadel/oidc, a three-row table (Name, Format,
  Description) of its example server's variables; go-oidc, per feature in
  its 1,203-line README.
- So: a long reference lives outside the README, and the README links to
  it. A short table sits in a README only when the variables are few and
  serve the quickstart (zitadel/oidc).

## Documentation guidance

- **GitHub:** "A README should only contain information necessary for
  developers to get started using and contributing to your project." It
  generates an outline from headings, and recommends relative links.
  "Helpful topics to classify a repository include the repository's intended
  purpose, subject area, community, or language", at most 20, each at most
  50 characters.
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/about-readmes>,
  <https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/customizing-your-repository/classifying-your-repository-with-topics>
- **Google docguide:** "A README is a short summary of the contents of a
  directory"; "At a minimum, your `README.md` file should contain a link to
  your user- and/or team-facing documentation."
  <https://google.github.io/styleguide/docguide/READMEs.html>
- **Google developer documentation style guide:** "Break up walls of text to
  aid in scannability. For example, separate paragraphs, create headings,
  and use lists. Use shorter sentences. Try to use fewer than 26 words per
  sentence." "Place distinguishing and important information of a paragraph
  in the first sentence to aid in scannability."
  <https://developers.google.com/style/accessibility>. "Use descriptive
  headings and titles because they help a reader navigate their browser and
  the page." <https://developers.google.com/style/headings>. "Put conditions
  before instructions, not after."
  <https://developers.google.com/style/highlights>
- **Kubernetes style guide:** "Try to keep paragraphs under 6 sentences."
  Headings at levels 4 to 6 only when necessary: "If your content is that
  detailed, it may need to be broken into separate articles." "Manually wrap
  paragraphs in the Markdown source", since diffs are line by line.
  <https://kubernetes.io/docs/contribute/style/style-guide/>. Its pages are
  of four types, concept, task, tutorial and reference, and it points to
  Diátaxis. <https://kubernetes.io/docs/contribute/style/page-content-types/>
- **Diátaxis:** "there are fundamentally four identifiable kinds of
  documentation, that respond to four different needs": tutorials
  (learning-oriented), how-to guides (goal-oriented), reference
  (information-oriented) and explanation (understanding-oriented). "Crossing
  or blurring the boundaries described in the map is at the heart of a vast
  number of problems in documentation." <https://diataxis.fr/start-here/>.
  Reference "should be **austere**. One hardly _reads_ reference material;
  one _consults_ it", "structured according to the structure of the
  machinery itself". <https://diataxis.fr/reference/>
- So: a README is the entry point (what, status, how to start, where the
  rest is), and pulsar's current opening is reference, an inventory of
  behavior consulted by endpoint, mixed into it. Paragraphs of six sentences
  or more, and sentences of 26 words or more, are what the guides above
  would break into lists, tables or separate pages.

## Presenting OpenID conformance and certification

- `panva/node-oidc-provider` has a `## Certification` section after its spec
  list, showing the official mark linked to the certification page with the
  Foundation's wording: "Filip Skokan has [certified] that oidc-provider
  conforms to the following profiles of the OpenID Connect™ protocol".
  <https://github.com/panva/node-oidc-provider>
- `luikyv/go-oidc` uses the same wording after a supported-specifications
  list; Hydra notes it was certified on a specific version (v1.0.0) with the
  unmodified reference login app.
- `zitadel/oidc` links **public conformance plan results**
  (`certification.openid.net/plan-detail.html?public=true&plan=…`) and keeps a
  spec table marked yes / no / not yet with links to spec sections. Its
  README calls the RP "certified for the basic and config profile", with the
  plan results as the links.
- The mark is granted only after passing, paying and publication by the
  OpenID Foundation, and covers one identified deployment. Before that, the
  accurate claim is "passes the OpenID conformance suite for profiles X",
  linked to public results with dates and commit SHAs. The Foundation's page
  confirms that "The free suite of conformance tests are available to
  anyone" and that "Certified implementations can use the 'OpenID Certified'
  certification mark." <https://openid.net/certification/>
- Checked again on 2026-11-11: nothing in the twelve READMEs contradicts
  this section. Each certification section is 5–25 lines; the detail of
  plans and modules lives on the Foundation's site.

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

A README of 100–200 lines, in the range of the comparable projects, with no
paragraph of six sentences or more (Kubernetes) and sentences under 26 words
(Google):

1. Title, a few meaningful badges, and an opening of two or three literal
   sentences: an OpenID Provider in Go, built by AI agents under a harness
   whose every control names its evidence. No behavior, error codes or
   lifetimes here (every project surveyed).
2. Status, as one `> [!IMPORTANT]` alert directly after the opening (GitHub:
   one or two alerts per page), in the pattern of Logrus and golang/mock:
   - a reference implementation, not for production use;
   - its scope, linked (the specifications below, and "Deliberately not
     doing" in `AGENTS.md`), is implemented;
   - development paused on a stated date, not "currently" (Kubernetes);
   - what that means: whether issues, pull requests and security reports
     (`SECURITY.md`) are still answered. Only what the maintainer will
     actually do; repostatus.org's "Inactive" wording, "support/maintenance
     will be provided as time allows", fits only if that is so.
3. Evidence at a glance: the latest conformance result in one dated sentence
   with its commit, linked to `conformance/README.md`; requirement-to-test
   traceability; eval results.
4. Quickstart: the minimum to run it, PostgreSQL, the three or four
   variables, `go run`, then `curl` of the discovery document, with links to
   the configuration and operations documents below (Keycloak's first
   command is at line 41, zitadel/oidc's at 56, Prometheus's at 60).
5. What is implemented: a table, one row per specification, linking to its
   text, its `docs/requirements/` file and its document under `docs/`; then
   what is deliberately not implemented, each with its reason or a link to
   one (zitadel/oidc, Dex).
6. Documentation: a list of links to the documents under `docs/`,
   `conformance/README.md`, `examples/README.md`, the ADRs and `GLOSSARY.md`
   (Google docguide: at minimum, link the documentation).
7. How it was built: links into the harness documentation, evals, execution
   plans and transcripts, with measured results and their limits.
8. One architecture diagram.
9. Verifying it: `make setup`, `make verify`, `make conformance`,
   `make examples`, each a line, the detail in the linked READMEs.
10. About the name: 80–150 words at the end (Caddy's `## About`).
11. License.

Set the repository's description, empty on 2026-11-11, to the opening's
first sentence, and add topics (for example `openid-connect`, `oauth2`,
`go`); GitHub's advice before archiving is to update both the README and
the description, so the two should agree on the status. Archiving is more
than a status statement: it makes issues and pull requests read-only to
everyone, so it fits only if the maintainer means to stop answering them.

## Where the README's long detail should go

Diátaxis's reference, "structured according to the structure of the
machinery itself", suggests one document per area under `docs/`, austere,
each fact with its clause and requirement IDs. The names are suggestions:

- **The opening's behavior,** by endpoint: `docs/authorization.md`
  (redirect URI matching and the loopback port, PKCE, `prompt`, `max_age`,
  `form_post`, login and consent), `docs/token.md` (client authentication,
  the `private_key_jwt` audience, the code, refresh and client credentials
  grants, rotation and reuse detection, `resource`), `docs/userinfo.md`
  (scopes, claims, the `claims` parameter), `docs/revocation.md`,
  `docs/logout.md` (confirmation, `id_token_hint`, the hint's key window),
  and the CORS rules where each endpoint is described. Kubernetes: content
  needing deep headings "may need to be broken into separate articles".
- **Lifetimes and intervals** (access token, refresh token, Login Session,
  key publication and retirement, cleanup) in one table with the reason for
  each: three or more related facts per item is Google's case for a table.
- **Configuration:** `docs/configuration.md`, a table of every `PULSAR_*`
  variable (required, default, meaning) and the `PG*` fallback; the registry
  format beside it or in `docs/registry.md`. The README's quickstart shows
  only the variables it needs (etcd, Prometheus, Keycloak, Hydra and
  node-oidc-provider keep the full reference out of the README).
- **Operations,** the how-to guides: running it and readiness, TLS,
  `pulsar keys rotate` and its preconditions, `pulsar client-secret`, hashing
  a password. In `docs/operations.md`, one heading per task, conditions
  before instructions (Google).
- **Conformance and examples:** their detail is already in
  `conformance/README.md` and `examples/README.md`; the README keeps one
  dated sentence for each and the command (certification sections of 5–25
  lines in node-oidc-provider, go-oidc and Hydra).
- **Reasons:** why a rule is as it is (no grace period, unthrottled Client
  secrets) stays in the ADRs, linked; explanation is a kind of its own in
  Diátaxis.
