# Two gates; the difference between them is time.
#
# `make check` is fast and offline enough to run every time an agent stops.
# `make verify` adds everything slow and is what CI runs. Work is not done
# until `make verify` passes.
#
# On a fresh machine with Go, Node.js, pnpm, jq and Claude Code installed,
# `make setup` installs everything else.

GO ?= go

# Release binaries, pinned here and installed into ./bin under versioned
# names, so a bump is a reinstall and local and CI cannot drift. Dependabot
# cannot see these lines: bump them by hand, with a changelog entry in
# docs/harness.md.
GOLANGCI_LINT_VERSION ?= v2.15.0
SHELLCHECK_VERSION ?= v0.11.0
ZIZMOR_VERSION ?= v1.32.0
GOLANGCI_LINT := bin/golangci-lint-$(GOLANGCI_LINT_VERSION)
SHELLCHECK := bin/shellcheck-$(SHELLCHECK_VERSION)
ZIZMOR := bin/zizmor-$(ZIZMOR_VERSION)

OS := $(shell uname -s | tr '[:upper:]' '[:lower:]')
ARCH := $(shell uname -m)
GOLANGCI_ARCH := $(patsubst x86_64,amd64,$(patsubst aarch64,arm64,$(ARCH)))
SHELLCHECK_ARCH := $(patsubst arm64,aarch64,$(ARCH))
ZIZMOR_TARGET := $(patsubst arm64,aarch64,$(ARCH))-$(patsubst darwin,apple-darwin,$(patsubst linux,unknown-linux-gnu,$(OS)))

# Go tools live in their own module, tools/go.mod, so the server's dependency
# graph stays the server's alone and Dependabot still updates them.
TOOL = $(GO) tool -modfile=tools/go.mod

# Node tools are pinned, with their whole dependency tree, by pnpm-lock.yaml;
# package.json pins pnpm itself and pnpm-workspace.yaml holds its overrides.
# They are reinstalled when the content of those three files changes, not
# their timestamps: a git checkout rewrites timestamps, and inside the sandbox
# pnpm cannot install.
NODE_TOOLS := node-tools
NODE_LOCK_SUM := $(shell cat package.json pnpm-lock.yaml pnpm-workspace.yaml | shasum -a 256 | cut -d' ' -f1)
PRETTIER := node_modules/.bin/prettier
MARKDOWNLINT := node_modules/.bin/markdownlint-cli2

SHELL_SCRIPTS = $(wildcard .claude/hooks/*.sh .githooks/* scripts/*.sh)

.DEFAULT_GOAL := help
.PHONY: help setup tools node-tools check verify fmt lint format-check \
	markdown-lint shell-lint spell test tidy-check repocheck workflow-check \
	vulncheck build hooks eval

help: ## Show the available targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z%-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

setup: tools hooks ## Once per clone: tools, git hooks, and the plugin that needs an install
	claude plugin install mattpocock-skills@claude-plugins-official --scope project

tools: $(GOLANGCI_LINT) $(SHELLCHECK) $(ZIZMOR) $(NODE_TOOLS) ## Install every pinned tool
	$(GO) -C tools mod download

check: tidy-check lint format-check markdown-lint shell-lint spell repocheck workflow-check test ## Fast gate

verify: check vulncheck build ## Full gate: check, reachable vulnerabilities, build

fmt: $(GOLANGCI_LINT) $(NODE_TOOLS) ## Format everything in place
	$(GOLANGCI_LINT) fmt ./...
	$(PRETTIER) --write --log-level warn .
	$(MARKDOWNLINT) --fix
	$(TOOL) shfmt -w $(SHELL_SCRIPTS)

lint: $(GOLANGCI_LINT) ## Lint Go and check its formatting
	$(GOLANGCI_LINT) fmt --diff ./...
	$(GOLANGCI_LINT) run ./...

format-check: $(NODE_TOOLS) ## Check Markdown, YAML and JSON formatting
	$(PRETTIER) --check --log-level warn .

markdown-lint: $(NODE_TOOLS) ## Lint Markdown
	$(MARKDOWNLINT)

# golangci-lint checks Go's spelling; this checks the prose and config around
# it, so the common British spellings fail the gate. Untracked files count, as
# they do for Prettier and markdownlint, so the Stop hook sees a new document;
# pnpm-lock.yaml is generated and skipped. File names go through -z and
# xargs -0, so no name is ever read by the shell.
spell: ## Catch British spellings and common misspellings outside Go
	git ls-files -z --cached --others --exclude-standard -- \
		'*.md' '*.sh' '*.yml' '*.yaml' '*.json' '*.jsonc' Makefile .githooks ':!pnpm-lock.yaml' \
		| xargs -0 $(TOOL) misspell -locale US -error

shell-lint: $(SHELLCHECK) ## Lint shell scripts and check their formatting
	$(SHELLCHECK) $(SHELL_SCRIPTS)
	$(TOOL) shfmt -d $(SHELL_SCRIPTS)

test: ## Unit tests with the race detector
	$(GO) test -race -count=1 ./...

tidy-check: ## Fail if go.mod or tools/go.mod is untidy
	$(GO) mod tidy -diff
	$(GO) -C tools mod tidy -diff

repocheck: ## Requirement traceability and TODO(#N) form
	$(GO) run ./internal/cmd/repocheck

# actionlint checks that workflows are well formed; zizmor checks them, and
# the Dependabot configuration, for security problems such as template
# injection, excessive permissions and unpinned actions, and fails on a file
# it cannot parse, since actionlint does not read dependabot.yml. It runs
# offline, ignoring any GitHub token in a developer's shell, unless
# ZIZMOR_GITHUB_TOKEN is set, as CI sets it in a step of its own; then it
# also runs the audits that query GitHub, such as impostor commits.
workflow-check: $(ZIZMOR) ## Lint GitHub Actions workflows for errors and security problems
	$(TOOL) actionlint
	$(ZIZMOR) --strict-collection $(if $(ZIZMOR_GITHUB_TOKEN),,--offline) .

vulncheck: ## Vulnerabilities reachable from this code
	$(TOOL) govulncheck ./...

build: ## Build every package
	$(GO) build ./...

hooks: ## Install the repository's git hooks
	git config core.hooksPath .githooks

# golangci-lint's own release archive, verified against its published
# checksums; upstream supports a release binary, not `go install`.
$(GOLANGCI_LINT):
	@mkdir -p bin
	@set -e; v=$(GOLANGCI_LINT_VERSION:v%=%); \
	name=golangci-lint-$$v-$(OS)-$(GOLANGCI_ARCH); \
	url=https://github.com/golangci/golangci-lint/releases/download/$(GOLANGCI_LINT_VERSION); \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL -o "$$tmp/$$name.tar.gz" "$$url/$$name.tar.gz"; \
	curl -fsSL "$$url/golangci-lint-$$v-checksums.txt" | grep " $$name.tar.gz$$" | (cd "$$tmp" && shasum -a 256 -c - >/dev/null); \
	tar -xzf "$$tmp/$$name.tar.gz" -C "$$tmp"; \
	mv "$$tmp/$$name/golangci-lint" $@
	@echo "installed $@"

# ShellCheck publishes no checksum file, so the sha256 of each archive, as
# GitHub reports it for the release asset, is pinned here; bump it with the
# version.
SHELLCHECK_SHA256_darwin_aarch64 := 56affdd8de5527894dca6dc3d7e0a99a873b0f004d7aabc30ae407d3f48b0a79
SHELLCHECK_SHA256_darwin_x86_64 := 3c89db4edcab7cf1c27bff178882e0f6f27f7afdf54e859fa041fca10febe4c6
SHELLCHECK_SHA256_linux_aarch64 := 12b331c1d2db6b9eb13cfca64306b1b157a86eb69db83023e261eaa7e7c14588
SHELLCHECK_SHA256_linux_x86_64 := 8c3be12b05d5c177a04c29e3c78ce89ac86f1595681cab149b65b97c4e227198

$(SHELLCHECK):
	@mkdir -p bin
	@set -e; name=shellcheck-$(SHELLCHECK_VERSION); \
	archive=$$name.$(OS).$(SHELLCHECK_ARCH).tar.xz; \
	sum=$(SHELLCHECK_SHA256_$(OS)_$(SHELLCHECK_ARCH)); \
	if [ -z "$$sum" ]; then echo "no pinned checksum for $$archive" >&2; exit 1; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL -o "$$tmp/$$archive" "https://github.com/koalaman/shellcheck/releases/download/$(SHELLCHECK_VERSION)/$$archive"; \
	echo "$$sum  $$archive" | (cd "$$tmp" && shasum -a 256 -c - >/dev/null); \
	tar -xJf "$$tmp/$$archive" -C "$$tmp"; \
	mv "$$tmp/$$name/shellcheck" $@
	@echo "installed $@"

# zizmor publishes no checksum file either; these are the sha256 digests
# GitHub reports for each release asset. Bump them with the version.
ZIZMOR_SHA256_aarch64-apple-darwin := 6efed18c4539a663fd3c851a2be9533fd8456c4e646d9416206da059154a0d3c
ZIZMOR_SHA256_x86_64-apple-darwin := 6983143c719ada6845a69cc4dd2bacc215f971662fecd8bbd2678388e5ce5969
ZIZMOR_SHA256_aarch64-unknown-linux-gnu := cb152b207f815116d7fa1c1ee4614f61578803351395052908095e79adfd9fd0
ZIZMOR_SHA256_x86_64-unknown-linux-gnu := bb110cc765eca9cd7efb2e284a956be5974c60027b0970f16397d86208a9957b

$(ZIZMOR):
	@mkdir -p bin
	@set -e; archive=zizmor-$(ZIZMOR_TARGET).tar.gz; \
	sum=$(ZIZMOR_SHA256_$(ZIZMOR_TARGET)); \
	if [ -z "$$sum" ]; then echo "no pinned checksum for $$archive" >&2; exit 1; fi; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL -o "$$tmp/$$archive" "https://github.com/zizmorcore/zizmor/releases/download/$(ZIZMOR_VERSION)/$$archive"; \
	echo "$$sum  $$archive" | (cd "$$tmp" && shasum -a 256 -c - >/dev/null); \
	tar -xzf "$$tmp/$$archive" -C "$$tmp"; \
	mv "$$tmp/zizmor" $@
	@echo "installed $@"

node-tools:
	@if [ "$$(cat node_modules/.lock-sum 2>/dev/null)" != "$(NODE_LOCK_SUM)" ]; then \
		pnpm install --frozen-lockfile && echo "$(NODE_LOCK_SUM)" > node_modules/.lock-sum; \
	fi

# Plugin evals run full Claude sessions on the logged-in credential: they draw
# on the plan's usage, or bill API credit if ANTHROPIC_API_KEY is set. So they
# are never part of a gate; the maintainer runs them. EVAL_MAX_COST_USD caps
# the evaluator's list-price estimate; it is not a bill. Models are pinned and
# Claude Code's auto-updates are off during a run, so results compare.
PLUGIN ?= right-sizing
EVAL_ABLATION ?= with-without
EVAL_MODEL ?= claude-sonnet-5-5
EVAL_JUDGE_MODEL ?= claude-sonnet-5-5
EVAL_MAX_COST_USD ?= 30
# Extra flags, e.g. --keep-temp to read each run's workspace afterwards. They
# go before --allow-tools, which takes every word after it as a tool.
EVAL_FLAGS ?=

eval: ## Run a plugin's evals (PLUGIN=right-sizing); uses plan usage or API credit
	DISABLE_AUTOUPDATER=1 claude plugin eval plugins/$(PLUGIN) --ablation $(EVAL_ABLATION) \
		--model $(EVAL_MODEL) --judge-model $(EVAL_JUDGE_MODEL) \
		--max-cost-usd $(EVAL_MAX_COST_USD) --no-publish $(EVAL_FLAGS) \
		--allow-tools Write WebSearch WebFetch

print-%: ## Print a variable, e.g. make print-GOLANGCI_LINT
	@echo $($*)
