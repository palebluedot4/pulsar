# Code review tools: which review ran, and how each one updates

Surveyed 2026-11-09 for step 3 of "Before a pull request" in `AGENTS.md`,
which names `/code-review:code-review --comment`, the command of the
`code-review@claude-plugins-official` plugin, after the maintainer found
that the plugin had not been loading. It answers four questions. On a fresh
machine, what do the repository's `extraKnownMarketplaces` and
`enabledPlugins` entries do, which code review can that user run, and why
does the plugin not load on the maintainer's machine? What does Anthropic
document about the `/code-review` skill bundled with Claude Code, and does
anything say it replaces the plugin? Which review does Anthropic recommend,
and which options update themselves? What should pulsar change?

Sources are Anthropic's Claude Code documentation at code.claude.com/docs
and its changelog (latest entry 2.1.319, 2026-11-06), the
`anthropics/claude-plugins-official` and `anthropics/claude-code`
repositories, `anthropics/claude-code-action` at commit `c0949c50`
(v1.0.268, the commit `.github/workflows/claude-review.yml` pins), and the
Code Review launch post, all read on 2026-11-09. Local evidence is Claude
Code 2.1.319 on the maintainer's machine, installed as the Homebrew cask
`claude-code@latest`; `.claude/settings.json`; `~/.claude/plugins/`; and
the 45 session transcripts under
`~/.claude/projects/-Users-Bruce-Documents-projects-palebluedot4-pulsar/`.
Anything not confirmed is marked **UNVERIFIED**, and an absence that could
not be confirmed is marked "(UNVERIFIED absence)".

## What actually ran

### The plugin records on this machine

| Record                                      | What it holds                                                                                                                                                                                                                                   |
| ------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `.claude/settings.json`                     | `extraKnownMarketplaces`: `claude-plugins-official` with `"autoUpdate": false`, `pulsar` with `"autoUpdate": true`. `enabledPlugins`: `code-review@claude-plugins-official`, `mattpocock-skills@claude-plugins-official`, `right-sizing@pulsar` |
| `~/.claude/plugins/installed_plugins.json`  | Install records for `gopls-lsp`, `mattpocock-skills` (user scope, and project scope for pulsar since 2026-11-04) and `career-ops`. None for `code-review@claude-plugins-official` or `right-sizing@pulsar`                                      |
| `~/.claude/plugins/known_marketplaces.json` | `claude-plugins-official` (`autoUpdate: false`, last updated 2026-11-05T02:56Z) and `pulsar` (`autoUpdate: true`, last updated 2026-11-09T10:00Z), among others                                                                                 |
| `~/.claude/plugins/cache/`                  | `claude-plugins-official/code-review/1.0.1/`, whose command is byte-identical to the one on the marketplace's `main`, and `pulsar/right-sizing/0.2.0/`. Both carry an `.orphaned_at` marker of 2026-11-06T02:22:57Z                             |
| `claude plugin list --json`                 | Lists `career-ops`, `gopls-lsp` and `mattpocock-skills` twice (user and project). Neither `code-review` nor `right-sizing` appears                                                                                                              |

Every session in the transcripts, from 2026-11-04 to 2026-11-09, starts
with a skill listing of 38 skills that includes the bundled `code-review`
and `mattpocock-skills:code-review`, and neither `code-review:code-review`
nor `right-sizing:right-sizing`. Twice the maintainer ran
`/reload-plugins`, which printed "Reloaded: 5 plugins · 30 skills · 7
agents · 0 hooks · 1 plugin LSP server": on 2026-11-05 at 07:06Z, and on
2026-11-06 at 02:22:31Z. After the second, that session's skill listing
added `code-review:code-review` and `right-sizing:right-sizing`. On
2026-11-09 at 09:46:58Z `/reload-skills` was run instead, and the plugin
stayed unknown.

### The third review of each pull request

| What ran                                                                    | Pull requests                                                                           | Evidence in the transcripts                                                                                                                                                                                                                           |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| The bundled `/code-review` with `--comment`, invoked through the Skill tool | 27: #10, #25–#28, #32–#34, #36, #37, #40, #42, #44–#46, #48, #54–#58, #60, #62–#66      | Each result begins `Skill "code-review" completed (forked execution).` #40 was reviewed twice; one call for #66 was interrupted and rerun                                                                                                             |
| The plugin, `/code-review:code-review --comment`                            | #29, on 2026-11-06, typed by the maintainer after `/reload-plugins`                     | Haiku, Sonnet and Opus subagents as its command prescribes; it found nothing and posted "No issues found. Checked for bugs and CLAUDE.md compliance." at 02:24:31Z. A bundled run for #29 had been started and stopped by the maintainer at 02:20:43Z |
| Attempts at the plugin that failed                                          | 2026-11-06 at 02:20:56Z and 02:22:13Z; 2026-11-09 at 09:48:13Z, 09:49:01Z and 09:50:24Z | `Unknown skill: code-review:code-review` from the Skill tool, or an unknown-command fallback when typed                                                                                                                                               |
| No code review invocation found                                             | #6–#9, #38, #43, and Dependabot's #30 and #31                                           | —                                                                                                                                                                                                                                                     |

So the plugin ran once, on #29, and the bundled skill ran on every other
pull request whose third review the transcripts record. On 2026-11-09 one
session began running the plugin's command file by hand, launching its
subagents itself, until the maintainer interrupted it; another, given the
typed command, said the plugin was not installed and ran the bundled skill
for #66 instead.

The descriptions of #27, #42, #45 and #46 say `/code-review:code-review
--comment` opened their threads; the bundled skill did. The inline threads
are real: #27, #45 and #65 carry 8, 7 and 8 top-level inline comments
under the maintainer's account, the first of each posted two to three
minutes after the bundled run started.

## A fresh machine

### What each entry does

Someone clones pulsar, installs Claude Code, accepts the workspace trust
dialog and runs `make setup`, which then ran `claude plugin install
mattpocock-skills@claude-plugins-official --scope project`. What it runs
now, and why, is under "Checked on 2026-11-10 (#92)" below.

| Entry                                                                   | Source in its marketplace                                      | What the documentation says happens                                                                                                                                                                                                                                                                                                                                  |
| ----------------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `extraKnownMarketplaces.claude-plugins-official`, `"autoUpdate": false` | GitHub, `anthropics/claude-plugins-official`                   | Registered once the folder is trusted; ignored "without a message" in an untrusted folder. The official marketplace is also added "the first time you start an interactive terminal session". It is cloned once and, with auto-update off, not refreshed in the background                                                                                           |
| `extraKnownMarketplaces.pulsar`, `"autoUpdate": true`                   | GitHub, `palebluedot4/pulsar`                                  | Registered after trust and cloned. After the first message of each interactive session, Claude Code "waits a random delay of up to ten minutes. It then refreshes every marketplace with auto-update on and updates the plugins installed from them on disk"; the running session keeps what it loaded                                                               |
| `code-review@claude-plugins-official`                                   | Relative path, `./plugins/code-review`; manifest version 1.0.1 | "A plugin that the marketplace lists by a relative path loads from the marketplace copy once the repository's `extraKnownMarketplaces` entries apply." "A relative-path plugin needs no install record because it loads from the marketplace itself"                                                                                                                 |
| `mattpocock-skills@claude-plugins-official`                             | URL, `mattpocock/skills.git` pinned to `sha` `49dd158d`        | An external source "doesn't install from the repository's settings alone". `/plugin` shows `Plugin "<name>" is enabled in project settings but isn't installed here` until `claude plugin install <name>@<marketplace> --scope project` runs, which is what `make setup` does. So "the plugin that needs an install", in `make help`, is literally true of the three |
| `right-sizing@pulsar`                                                   | Relative path, `./plugins/right-sizing`                        | As for `code-review`                                                                                                                                                                                                                                                                                                                                                 |

The documentation describes no prompt asking the user to install the
marketplaces or plugins a repository declares; the trust dialog is the
only gate it names (UNVERIFIED absence). `enabledPlugins` from a
repository's settings is "applied at session start" in interactive
terminal sessions.

`autoUpdate` decides only whether the background pass refreshes a
marketplace and updates the plugins installed from it. Left unset, it is
"on for Anthropic's official marketplaces such as `claude-plugins-official`
… and off for every other marketplace". `DISABLE_AUTOUPDATER=1`,
`DISABLE_UPDATES=1` or `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` turns
the whole pass off unless `FORCE_AUTOUPDATE_PLUGINS=1` is also set. A plugin
whose manifest pins `version`, as `code-review` has pinned `"1.0.1"` since
2026-10-26, stays "on the cached copy until its author changes the string,
however many commits they push", even from a marketplace that auto-updates.

### Which code review that user can run

The bundled `/code-review` is in every session unless
`disableBundledSkills` or a `skillOverrides` entry hides it. A plugin's
commands cannot collide with it: for "a plugin skill and a skill at any of
the locations above", the skills page says "Both load, because plugin
skills are namespaced as `/plugin-name:skill-name`". Only a project or
personal skill named `code-review` would replace the bundled command, and
pulsar has none. The 2026-11-06 session confirms the rule: after
`/reload-plugins`, `code-review` and `code-review:code-review` were both
listed, and the plugin's command ran.

By the documentation, the fresh machine also gets `/code-review:code-review`
and `/right-sizing:right-sizing` with no install, because both are
relative-path plugins. On its first session, the marketplaces are missing
from `known_marketplaces.json`, and for that case the documentation says
"Claude Code clones it, then reloads plugins and downloads enabled plugins
that aren't cached yet". Whether later sessions load them at start is
**UNVERIFIED**; on this machine they do not.

### Why the plugin does not load here

The cause is **UNVERIFIED**. What is established:

- Neither plugin has an install record, and the loading page says "Plugins
  load at session start from `installed_plugins.json` and the cache without
  using the network."
- The same page says a relative-path plugin "needs no install record".
- Both plugins were cached on this machine (2026-11-04 and 2026-11-05) yet
  absent from every session's initial listing, and both appeared after
  `/reload-plugins`.
- The `.orphaned_at` markers are dated 2026-11-06, after the first sessions
  that lacked the plugins, so they are not the original cause. The
  documentation says Claude Code writes that marker "When you update or
  uninstall a plugin" and removes the directory 14 days later; what wrote
  it here, 26 seconds after a reload, is **UNVERIFIED**.

The hypothesis that fits every observation is that session start loads
only plugins with an install record, and relative-path plugins without one
load only on a reload, whether `/reload-plugins` or the reload after a
first marketplace clone. That contradicts the "needs no install record"
sentence, and is **UNVERIFIED**. Whether `claude plugin install
code-review@claude-plugins-official --scope project` would make it load at
session start was not tried, since this survey installs nothing
(**UNVERIFIED**). No issue in `anthropics/claude-code` was found
describing it (UNVERIFIED absence).

The same applies to `right-sizing@pulsar`, which `docs/harness.md` lists as
enabled from `main`: it has been missing from every session's initial
listing on this machine too.

**Checked on 2026-11-10 (#68), with Claude Code 2.1.319:** after an install
at project scope, `right-sizing@pulsar` loaded at session start on this
machine.

- Before the install, `right-sizing:right-sizing` was still missing from
  each new session's initial listing. Its cache directory, listed on
  2026-11-10 before the install, held an `.orphaned_at` marker of
  2026-11-09T10:39:56Z and an `.in_use` directory last modified at 10:23Z
  that day. A marker rewritten while the plugin was in use is consistent
  with a cleanup pass that treats a cached plugin with no install record as
  orphaned; what rewrote it is still **UNVERIFIED**. Either way the removal
  around 2026-11-20 that this survey expected no longer applies: the
  install removed the marker.
- At 06:25:36Z the maintainer ran `claude plugin install right-sizing@pulsar
--scope project`. `installed_plugins.json` gained a project-scope record
  for version 0.2.0 at `gitCommitSha` `c6bc31f`. The cache directory was
  rewritten with no `.orphaned_at` marker, and the next new session listed
  `right-sizing:right-sizing` at start.
- The install also rewrote `.claude/settings.json`, reordering its keys and
  reformatting its arrays. `jq -S` shows the content unchanged, but Prettier
  then fails `make check` until the file is restored.

This is consistent with the hypothesis above, tested on one plugin: the
install added a record and removed the `.orphaned_at` marker, and either
could be what made it load. The marker is not the original cause, since it
postdates the first sessions without the plugin. Why a relative-path plugin
needed a record, against the documentation's "needs no install record", is
**UNVERIFIED**. On a fresh clone with an empty `HOME`, before any session,
the install fails with `Plugin "right-sizing" not found in marketplace
"pulsar"`, and `mattpocock-skills` fails the same way, since neither
marketplace has been cloned yet (#92). `make setup` now installs
every enabled plugin at project scope and restores `.claude/settings.json`
afterwards.

**Checked on 2026-11-10 (#92), with Claude Code 2.1.319,** in fresh clones
of pulsar with an empty `HOME` standing in for a fresh machine, outside any
session. Where a marketplace had to be behind its source, its clone was
reset one commit back.

- **Trust alone does not register the marketplaces.** With the clone
  recorded as trusted (`hasTrustDialogAccepted` in `~/.claude.json`),
  `claude plugin marketplace list` still listed only the built-in
  `anthropic-plugin-directory`, and the install failed as before. Neither
  command acted on `extraKnownMarketplaces`. Whether
  opening a session first, as the documentation describes, makes the
  installs succeed is **UNVERIFIED**; no interactive session was run.
- **`claude plugin marketplace add <owner/repo> --scope project` clones a
  declared marketplace without a session.** It reported `Successfully added
marketplace: pulsar (declared in project settings)`, after which both
  installs succeeded. On a machine where the marketplace is already cloned
  it reports `already on disk` and changes nothing: neither the copy, even
  one behind its source, nor its `autoUpdate` in `known_marketplaces.json`.
  It rewrites `.claude/settings.json`, reordered as an install does, and
  drops both `autoUpdate` keys, so `make setup` still puts the file back.
  On a fresh machine it records no `autoUpdate` in
  `known_marketplaces.json`. A headless session in the trusted clone, run
  afterwards and stopped at "Not logged in", wrote `autoUpdate: false` and
  `true` there from `.claude/settings.json`, and left the official copy
  where it was.
- **`claude plugin install --marketplace <source>`**, by its `--help`, adds
  "A marketplace not added yet … first, in user settings", which would be
  a second declaration beside the project's. It was not needed, so it was
  not tried, and what it does is **UNVERIFIED**.
- **An install refreshes the marketplace it installs from, `autoUpdate`
  notwithstanding.** With the official marketplace's copy one commit
  behind and `autoUpdate: false` recorded, `claude plugin install
mattpocock-skills@claude-plugins-official --scope project` moved the copy
  to the head of `main` (`dceb15d`), whether the plugin was new or already
  installed, when it only printed `is already installed`. Its debug log
  shows "Successfully refreshed marketplace: claude-plugins-official", or,
  when the copy had been refreshed moments before, "Skipping refresh …
  refreshed 0s ago". So `make setup`, which has run an install since
  `f5cdf21` (2026-11-05), moved the frozen marketplace on any machine
  where it was behind, by this behavior; a run on such a machine before
  this change was not observed. On the maintainer's machine its copy is at `dceb15d`, last
  updated 2026-11-10T06:41Z; whether `make setup` moved it there is
  **UNVERIFIED**.
- **Of the three variables above that turn the background pass off, only
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` stops that refresh.** With
  `lastUpdated` set to a week earlier, so that no throttle applied, the
  install still refreshed the copy under `DISABLE_AUTOUPDATER=1` and
  `DISABLE_UPDATES=1`, and did not under
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1`. An earlier run that seemed
  to show `DISABLE_UPDATES=1` holding fell inside that throttle. As read on
  2026-11-11, the plugin loading page documents both findings: the refresh
  before a `name@marketplace` install "doesn't depend on the marketplace's
  auto-update setting or on `DISABLE_AUTOUPDATER`", and it is skipped when
  `CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC` is set or the marketplace was
  refreshed within the last 30 seconds, the throttle above, among other
  cases (local and settings sources, seed directories, marketplaces
  blocked by managed settings). It does not
  name `DISABLE_UPDATES`, so that variable's part is still observed only,
  in 2.1.319. <https://code.claude.com/docs/en/plugins/loading>

An explicit `claude plugin marketplace update pulsar` still refreshed a
copy one commit behind under that variable, and `claude plugin marketplace
add … --json` ends with a line naming the marketplace it added, from the
repository's manifest.

`make setup` now runs `scripts/setup-plugins.sh`, which, with
`CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1` set throughout:

1. adds every marketplace in `extraKnownMarketplaces` with `claude plugin
marketplace add <owner/repo> --scope project`, and stops if it was added
   under another name than its key, under which the installs would look
   for it;
2. updates each marketplace with `"autoUpdate": true` explicitly, since an
   install no longer does;
3. takes a digest of every file in each other marketplace's copy, installs
   the enabled plugins, and stops if any digest changed, so that a later
   release of Claude Code that stops honoring the variable fails `make
setup` instead of moving the freeze unnoticed;
4. restores `.claude/settings.json` byte for byte, as before.

It accepts only GitHub sources named by `repo` alone, in `owner/repo` form,
the only kind declared, and stops before any command on any other,
including one that pins a `ref` it would not pass on.
`internal/harness/setupplugins_test.go` checks each step against a fake
`claude`. Run against Claude Code with the Makefile's other prerequisites
already built (`make -o tools -o hooks setup`):

| Machine                                                                                                                             | Result                                                                                                                         |
| ----------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------ |
| Fresh clone, empty `HOME`                                                                                                           | Exit 0; both marketplaces cloned, `pulsar` updated, both plugins installed at project scope, `.claude/settings.json` unchanged |
| Both installed, the official copy at `c131608` and the `pulsar` copy at `a0604ca`, one commit behind each, `lastUpdated` a week old | Exit 0; the official copy stayed at `c131608`, the `pulsar` copy moved to `dfbfa19`, its `main`                                |
| The same, with the official copy behind again and the script's variable removed                                                     | Exit 1 with `an install changed a marketplace with autoUpdate off: claude-plugins-official`; the copy had moved to `dceb15d`   |

An earlier version of the change, which set the variable in the Makefile's
recipe without the update or the digest, was also run with
`mattpocock-skills` uninstalled and the official copy behind: it installed
the plugin and left the copy at `c131608`.

One consequence follows from the behavior above but was not run
(**UNVERIFIED**): a plugin newly enabled from the official marketplace that
a frozen copy does not yet list would fail to install, as `right-sizing`
did before its marketplace was cloned, until that marketplace is updated
on purpose (`claude plugin marketplace update claude-plugins-official`),
which is what the freeze in `docs/harness.md` (Versions) asks for.

Sources: <https://code.claude.com/docs/en/plugins/loading>,
<https://code.claude.com/docs/en/plugins/org>,
<https://code.claude.com/docs/en/plugins/install>,
<https://code.claude.com/docs/en/plugins/troubleshooting>,
<https://code.claude.com/docs/en/plugins/anthropic-marketplaces>,
<https://code.claude.com/docs/en/settings-reference>,
<https://code.claude.com/docs/en/skills>,
<https://github.com/anthropics/claude-plugins-official/blob/main/.claude-plugin/marketplace.json>,
<https://github.com/anthropics/claude-plugins-official/commit/9780cf407f55>.

## The bundled `/code-review`

### History

| Version, date       | Change, from the changelog                                                                                                                                                                    |
| ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2.1.63, 2026-02-28  | "Added `/simplify` and `/batch` bundled slash commands"                                                                                                                                       |
| 2.1.147, 2026-05-21 | "Renamed `/simplify` to `/code-review`. It now reports correctness bugs at a chosen effort level (e.g., `/code-review high`); pass `--comment` to post findings as inline GitHub PR comments" |
| 2.1.152, 2026-05-27 | `--fix` applies the findings to the working tree                                                                                                                                              |
| 2.1.218, 2026-07-22 | Runs "as a background subagent"                                                                                                                                                               |
| 2.1.223, 2026-08-06 | `/review` becomes an alias; with no level, the review reuses "the level you typed last"                                                                                                       |
| 2.1.257, 2026-09-01 | `--comment` posts on GitLab merge requests through `glab`                                                                                                                                     |
| 2.1.274, 2026-09-17 | "leaner inline review prompts for every model that has no tuned settings of its own, instead of spawning many review subagents"                                                               |
| 2.1.288, 2026-10-02 | `--max-findings <n>\|all`                                                                                                                                                                     |
| 2.1.290, 2026-10-05 | Medium effort also reports cleanup and CLAUDE.md conventions findings "on models without tuned review settings, including Opus 5.5 and Sonnet 5.5"                                            |
| 2.1.311, 2026-10-26 | "tell Claude to put the effort level first and use max only when asked"                                                                                                                       |

### What the documentation says

- It is "a bundled skill: its instructions are built into Claude Code, so
  there is no `SKILL.md` file on disk", so it changes only when Claude Code
  does. It "works on any plan" and is billed as the rest of the session.
- Effort: at `low` it "reports the findings it's most confident in"; "From
  `medium` through `max`, the review broadens coverage." With no level, it
  reuses the last level from `low` to `max` typed, "even in an earlier
  session", or the session's effort if none was ever typed. `ultra` runs
  the cloud ultrareview instead.
- Order: "type a target after the effort level and any flags"; a target is
  a pull request number, a branch, a path or a revision range.
- `--comment` "posts the findings on a GitHub pull request as inline
  comments". `--fix` "also asks Claude to apply the findings to your
  working tree". `--max-findings` changes the limit.
- It "follows your `CLAUDE.md`" and "doesn't read `REVIEW.md`", which
  configures only the managed Code Review service.

### How it differs from the plugin

|                                   | Bundled `/code-review`                                                                                                        | `code-review@claude-plugins-official`                                                                                                                                                                    |
| --------------------------------- | ----------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Defined in                        | The Claude Code binary                                                                                                        | `plugins/code-review/commands/code-review.md`, ported from `anthropics/claude-code` on 2026-10-26                                                                                                        |
| Version                           | The Claude Code version                                                                                                       | Manifest `"version": "1.0.1"`                                                                                                                                                                            |
| Target                            | The branch, a pull request, a path or a range                                                                                 | A pull request                                                                                                                                                                                           |
| How it reviews                    | A forked background subagent; depth set by the effort level; on Opus 5.5, as of 2.1.290, the leaner inline prompts of 2.1.274 | Haiku checks eligibility and lists CLAUDE.md files, Sonnet summarizes, then four reviewers: two Sonnet for CLAUDE.md, two Opus for bugs; each bug finding is validated by its own subagent               |
| Skips                             | Nothing documented (UNVERIFIED absence)                                                                                       | Closed, draft or trivial pull requests, and any on which "Claude has already commented"                                                                                                                  |
| `--comment`                       | Inline comments on GitHub; a note on GitLab                                                                                   | `gh pr comment` when nothing is found; otherwise `mcp__github_inline_comment__create_inline_comment`, the MCP tool that claude-code-action starts "only when `--allowedTools` in `claude_args` names it" |
| Effort, `--fix`, `--max-findings` | Yes                                                                                                                           | No                                                                                                                                                                                                       |

Whether the plugin's command can post inline comments in a local session,
where that MCP tool is not started, is **UNVERIFIED**: its one local run,
on #29, found nothing and posted a summary with `gh pr comment`.

No Anthropic statement found says the bundled skill supersedes or replaces
the plugin (UNVERIFIED absence). The evidence points the other way. On
2026-10-26 Anthropic moved the plugin, "The newer code-review now lives in
claude-plugins-official" (`anthropics/claude-code` commit `aef1f311bfd3`),
and gave it a version. The GitHub Actions page still installs it in its
review workflow. The local review page never mentions it, and the
comparison table on the Code Review page lists `/code-review` and "Claude
in your own CI" without naming the plugin.

Sources: <https://code.claude.com/docs/en/code-review-local>,
<https://code.claude.com/docs/en/changelog>,
<https://code.claude.com/docs/en/skills>,
<https://code.claude.com/docs/en/github-actions>,
<https://github.com/anthropics/claude-plugins-official/tree/main/plugins/code-review>,
<https://github.com/anthropics/claude-code/commit/aef1f311bfd3>.

## What Anthropic recommends, and what updates itself

### The options Anthropic lists

The Code Review page compares the ways to get a review by "Who can use it",
not by team size. No recommendation for a solo developer as such was found
(UNVERIFIED absence).

| Option                                     | Who can use it, as documented                                                                    | What else Anthropic says                                                                                                                                                                                                                        |
| ------------------------------------------ | ------------------------------------------------------------------------------------------------ | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Code Review, a managed service             | "Organizations on a Team or Enterprise plan with GitHub repositories, once an Owner turns it on" | Launched 2026-03-09 in research preview, now "generally available"; billed through usage credits; reviews "generally average $15–25"; "the average review takes around 20 minutes"; "more thorough (and more expensive)" than the GitHub Action |
| `/code-review`                             | "Anyone, on any plan"                                                                            | Runs in your own session                                                                                                                                                                                                                        |
| Ultrareview, `/code-review ultra`          | Requires signing in with a claude.ai account                                                     | A cloud sandbox; "typically $5 to $25" after the free runs; "5 to 15 minutes"                                                                                                                                                                   |
| Claude in your own CI, with GitHub Actions | "Anyone with a Claude API key or cloud provider credentials"                                     | The documented review workflow installs `code-review@claude-plugins-official`. "For automatic reviews without maintaining a workflow file, see Code Review"                                                                                     |
| Your own reviewer, a subagent or skill     | "Anyone who writes one"                                                                          | —                                                                                                                                                                                                                                               |

### Which options update themselves

| Option                                               | Updates itself?                                                                                                                                                                                                                         | How it is held still                                                                                                                                             |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Bundled `/code-review`                               | With Claude Code. "Native installations automatically update in the background", on the `latest` or `stable` channel. "Homebrew, WinGet, apt, dnf, and apk installations do not auto-update by default", and this machine uses Homebrew | `DISABLE_AUTOUPDATER` stops the background check; `DISABLE_UPDATES` blocks every update path; a specific version can be installed                                |
| A plugin from a marketplace with `autoUpdate: true`  | "Plugins update automatically when the marketplace they came from has auto-update turned on", unless the manifest pins `version`, which holds the cached copy until the string changes                                                  | `autoUpdate: false`, or the environment variables above. A marketplace entry can pin `sha` for an external source                                                |
| A plugin from a marketplace with `autoUpdate: false` | No; the marketplace copy stays at the commit first fetched, which differs from machine to machine                                                                                                                                       | Already still, but not at a recorded version                                                                                                                     |
| Code Review, the managed service                     | Runs on Anthropic's infrastructure; the documentation offers no version to select (UNVERIFIED absence)                                                                                                                                  | —                                                                                                                                                                |
| `anthropics/claude-code-action@v1`                   | `v1` is a floating tag; the newest version tag is v1.0.269                                                                                                                                                                              | pulsar pins commit `c0949c50` (v1.0.268), whose lockfile pins `@anthropic-ai/claude-agent-sdk` 0.3.318. Which Claude Code version that bundles is **UNVERIFIED** |
| The plugin inside the action                         | The action installs from the marketplace's Git URL on each run, so it gets the plugin at whatever version `main` then holds (inference from the input's description; **UNVERIFIED**)                                                    | Whether `plugin_marketplaces` accepts a pinned ref is **UNVERIFIED**                                                                                             |

The option that "syncs itself to the latest version" could be either the
official marketplace's default auto-update or Claude Code's own background
updater; both are documented in those terms, and which one the maintainer
recalls is **UNVERIFIED**.

### Against pulsar's reasons for freezing the marketplace

`docs/harness.md` (Versions) freezes the official marketplace so its
plugins change "only when updated on purpose, with a changelog entry", and
records the Claude Code version with every eval result and ExecPlan
outcome; `make eval` sets `DISABLE_AUTOUPDATER=1`. Three things follow:

- The freeze never gave pulsar a reviewed version of this plugin: the
  plugin did not load at session start, so the review that ran was the one
  the freeze does not cover.
- The bundled skill's version is the Claude Code version, which pulsar
  already records, so using it adds no unrecorded version. Its behavior
  does move with Claude Code: the changelog has `/code-review` entries in
  five releases from 2.1.290 to 2.1.316 (2026-10-05 to 2026-10-31). On a
  Homebrew install that happens only when the maintainer upgrades.
- `/security-review`, step 2, is already a command built into Claude Code,
  so its version is the Claude Code version too.

Sources: <https://code.claude.com/docs/en/code-review>,
<https://code.claude.com/docs/en/code-review-costs>,
<https://code.claude.com/docs/en/ultrareview>,
<https://code.claude.com/docs/en/github-actions>,
<https://code.claude.com/docs/en/setup>,
<https://code.claude.com/docs/en/plugins/install>,
<https://code.claude.com/docs/en/plugins/loading>,
<https://claude.com/blog/code-review>,
<https://github.com/anthropics/claude-code-action/blob/c0949c50a78c1ec8ce2647db36629b870e715d0c/action.yml>,
<https://github.com/anthropics/claude-code-action/blob/c0949c50a78c1ec8ce2647db36629b870e715d0c/bun.lock>.

## Corrections to ai-development.md

Applied to that file, and the misattribution in `docs/research/evals.md`
corrected, on 2026-11-09.

- **The plugin's version.** The "Code review" table says the plugin's
  version follows "Marketplace repo commits (no version pin)", and
  "Plugins: declaration and updates" says "`code-review` has no version
  and tracks the marketplace repo". Since 2026-10-26 (`9780cf407f55`) its
  manifest sets `"version": "1.0.1"`, and Claude Code takes the manifest's
  version first.
- **The plugin's README.** It does not describe "five Sonnet agents, then a
  Haiku scorer". It describes "4 parallel agents" (two for CLAUDE.md
  compliance, one bug scan, one reading git blame and history), each issue
  scored 0–100 and those below 80 dropped, and names no model. That still
  differs from the command, which validates findings with subagents instead
  of scoring them.
- Still true: the bundled skill's row, the command's four reviewers and
  their quotes, the 2026-10-26 sync, and Code Review's $15–25, about 20
  minutes, and 16% to 54%, all from the launch post.

The same misattribution is in `docs/research/evals.md`, "The three review
controls", which counts "what `code-review@claude-plugins-official` found"
in the inline comments of #34 to #65; those came from the bundled skill.

## What pulsar takes from this

**Decided on 2026-11-09:** the maintainer follows Anthropic's documented
practice. Step 3 names `/code-review high --comment <number>` (1); the
plugin leaves `enabledPlugins` (2); `right-sizing` gets an issue, #68 (3); #1
decides which review CI runs, and the workflow's header no longer says the
plugin runs locally (4); the `docs/harness.md` row is renamed (5); and its
Changelog records which review ran, leaving the older pull request
descriptions as they are (6).

Proposals for the maintainer to decide:

1. **Step 3 names the bundled skill.** For example: "After opening it,
   review the pull request with `/code-review high --comment <number>`,
   bundled with Claude Code, and resolve every thread it opens." Naming a
   level keeps the review from depending on the level last typed, and puts
   the arguments in the documented order. Which level is the maintainer's
   choice; `max` is documented as the costliest, and the results for #34,
   #42 and #57 report that they ran at high.
2. **Remove `code-review@claude-plugins-official` from `enabledPlugins`.**
   It does not load at session start here, and where it does load it adds
   a second, differently behaving review under a similar name. Keep the
   `claude-plugins-official` marketplace entry, which `mattpocock-skills`
   needs. `make setup` then needs no change, and "the plugin that needs an
   install" stays true. If the plugin is kept instead, have `make setup`
   install it at project scope as it does `mattpocock-skills`, and confirm
   in a new session that it loads; that an install record fixes the
   loading is **UNVERIFIED**.
3. **Open an issue for `right-sizing@pulsar`.** It shows the same symptom,
   so a control `docs/harness.md` lists as enabled has been off at session
   start. Test whether installing it at project scope makes it load, and
   whether its orphaned cache directory is removed around 2026-11-20.
4. **CI (#1) runs the same tool as local review.** When #1 turns the
   workflow on, try `prompt: /code-review high --comment <owner/repo/pull/n>`
   on one pull request, without the `plugins` and `plugin_marketplaces`
   inputs, and check that findings arrive as inline comments and which
   tools `--allowedTools` must name; that the bundled `--comment` works
   inside the action is **UNVERIFIED**. The pinned action commit then fixes
   the Claude Code version CI reviews with. If it does not work, keep the
   plugin in CI as Anthropic documents, and record that CI and local review
   differ and that the CI plugin follows the marketplace's `main`. Either
   way, the workflow's header, "The same plugin runs locally today", is
   false and should go.
5. **The `docs/harness.md` row.** Rename it to "`/code-review --comment`
   (bundled) on PRs". Purpose: "Correctness review of the pull request at
   a stated effort level, findings posted as inline comments; step 3 in
   `AGENTS.md`, run locally until CI runs it (#1)". Evidence: "Vendor
   practice: Anthropic documents it as the review on any plan
   (`docs/research/code-review-tools.md`); bundled with Claude Code, so its
   version is the Claude Code version each eval records". Drop "Parallel
   reviewers, each finding validated separately", which describes the
   plugin, not the review that ran.
6. **Record the history.** Add a dated entry to `docs/harness.md`, for
   example: "2026-11-09: step 3 named `/code-review:code-review --comment`,
   the plugin, but on the maintainer's machine the plugin did not load at
   session start. The third review of #10, #25–#28, #32–#34, #36, #37,
   #40, #42, #44–#46, #48, #54–#58, #60 and #62–#66 was the bundled
   `/code-review --comment`; #29 alone was reviewed by the plugin, after
   `/reload-plugins`." Apply the corrections to
   `docs/research/ai-development.md` and `docs/research/evals.md` listed
   above. For the descriptions of #27, #42, #45 and #46, either edit each
   to name the bundled skill, which GitHub keeps in the description's edit
   history, or leave them and let the harness entry stand as the
   correction.
