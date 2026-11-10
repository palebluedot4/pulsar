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

# The examples are a module of their own, which must not require pulsar's;
# the gates lint, tidy, build and scan it as they do pulsar's. Its tests
# need a running pulsar, so only make examples runs them.
EXAMPLES := examples

# Node tools are pinned, with their whole dependency tree, by pnpm-lock.yaml;
# package.json pins pnpm itself and pnpm-workspace.yaml holds its overrides.
# They are reinstalled when the content of those three files changes, not
# their timestamps: a git checkout rewrites timestamps, and inside the sandbox
# pnpm cannot install.
NODE_TOOLS := node-tools
NODE_LOCK_SUM := $(shell cat package.json pnpm-lock.yaml pnpm-workspace.yaml | shasum -a 256 | cut -d' ' -f1)
PRETTIER := node_modules/.bin/prettier
MARKDOWNLINT := node_modules/.bin/markdownlint-cli2

SHELL_SCRIPTS = $(wildcard .claude/hooks/*.sh .githooks/* scripts/*.sh conformance/runner/*.sh)

.DEFAULT_GOAL := help
.PHONY: help setup tools node-tools check verify fmt lint format-check \
	markdown-lint shell-lint spell test tidy-check repocheck workflow-check \
	sqlc sqlc-check dockerfile-check vulncheck build conformance examples \
	hooks eval

help: ## Show the available targets
	@awk 'BEGIN { FS = ":.*## " } /^[a-z%-]+:.*## / { printf "  %-14s %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

# The plugins .claude/settings.json enables, and the marketplaces it
# declares, are set up by a script, which internal/harness tests (#68, #92).
setup: tools hooks ## Once per clone: tools, git hooks, and the enabled Claude Code plugins
	scripts/setup-plugins.sh

tools: $(GOLANGCI_LINT) $(SHELLCHECK) $(ZIZMOR) $(NODE_TOOLS) ## Install every pinned tool
	$(GO) -C tools mod download

check: tidy-check sqlc-check dockerfile-check lint format-check markdown-lint shell-lint spell repocheck workflow-check test ## Fast gate

verify: check vulncheck build ## Full gate: check, reachable vulnerabilities, build

fmt: $(GOLANGCI_LINT) $(NODE_TOOLS) ## Format everything in place
	$(GOLANGCI_LINT) fmt ./...
	$(PRETTIER) --write --log-level warn .
	$(MARKDOWNLINT) --fix
	$(TOOL) shfmt -w $(SHELL_SCRIPTS)

# fmt walks into the examples' module; run stops at its go.mod, so it runs
# there too.
lint: $(GOLANGCI_LINT) ## Lint Go and check its formatting
	$(GOLANGCI_LINT) fmt --diff ./...
	$(GOLANGCI_LINT) run ./...
	cd $(EXAMPLES) && $(CURDIR)/$(GOLANGCI_LINT) run ./...

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

test: ## Tests with the race detector; needs PostgreSQL at PULSAR_TEST_DATABASE_URL
	$(GO) test -race -count=1 ./...

tidy-check: ## Fail if go.mod, tools/go.mod or examples/go.mod is untidy
	$(GO) mod tidy -diff
	$(GO) -C tools mod tidy -diff
	$(GO) -C $(EXAMPLES) mod tidy -diff

# sqlc generates each domain package's query code from its queries.sql and
# the migrations, as sqlc.yaml lists them. The generated code is committed,
# so the gate fails when it differs from what sqlc would generate now.
sqlc: ## Regenerate the query code from queries.sql files and migrations
	$(TOOL) sqlc generate

sqlc-check: ## Fail if the generated query code is stale
	$(TOOL) sqlc diff

# The official golang image pins GOTOOLCHAIN=local, so the Dockerfile builds
# only while its Go release is the one go.mod names; make verify never builds
# the image, so this keeps the two in step.
GO_MOD_VERSION := $(shell awk '$$1 == "go" { print $$2 }' go.mod)

dockerfile-check: ## Fail if the Dockerfile's Go release is not the one go.mod names
	@grep -q '^FROM golang:$(GO_MOD_VERSION)-' Dockerfile \
		|| { echo "Dockerfile: the golang image must be Go $(GO_MOD_VERSION), the release go.mod names" >&2; exit 1; }

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

vulncheck: ## Vulnerabilities reachable from this code and the examples
	$(TOOL) govulncheck ./...
	$(TOOL) govulncheck -C $(EXAMPLES) ./...

build: ## Build every package, the examples' too
	$(GO) build ./...
	$(GO) -C $(EXAMPLES) build ./...

# The OpenID conformance suite against pulsar, in the Docker Compose stack of
# conformance/compose.yaml, which says what runs. Every run starts from
# nothing: a self-signed certificate for the name pulsar, valid for a day,
# and a PULSAR_SECRET are generated for it and never committed. When the run
# ends, on success, an error or an interrupt, the log of every service but
# the runner, whose output is the target's own, is saved beside the exported
# results in conformance/results, and the stack and its volumes are removed.
# The cleanup goes on past a failed step and ignores a second interrupt, so
# that it always reaches the removal.
# Needs Docker with Compose v2, openssl and jq; inside the sandbox it cannot
# reach Docker (docs/harness.md).
CONFORMANCE_COMPOSE := docker compose --file conformance/compose.yaml
# Each expected-results file, with the one result its entries may accept,
# and what jq requires of every entry: each field the suite's runner reads
# (it fails with a KeyError, after running the whole plan, on one that is
# missing), the file's own result, and a reason. A skip entry names a
# module, not a condition: the runner reads only the module's fields in
# it, so it may carry nothing else but its reason, lest a condition there
# make it look narrower than it is.
CONFORMANCE_EXPECTED := failure:conformance/expected-failures.json warning:conformance/expected-warnings.json skip:conformance/expected-skips.json
CONFORMANCE_ENTRY := type == "array" and all(.[]; \
	(["test-name", "variant", "configuration-filename"] - keys) == [] \
	and (.comment | type) == "string" and .comment != "" \
	and if $$result == "skip" then (keys - ["test-name", "variant", "configuration-filename", "comment"]) == [] \
	else (["current-block", "condition"] - keys) == [] and .["expected-result"] == $$result end)

conformance: ## Run the OpenID conformance suite's Config OP, Basic OP, Form Post Basic and RP-Initiated Logout plans against pulsar; needs Docker
	@for e in $(CONFORMANCE_EXPECTED); do \
		result=$${e%%:*}; f=$${e#*:}; \
		jq -e --arg result "$$result" '$(CONFORMANCE_ENTRY)' "$$f" >/dev/null \
			|| { echo "$$f: must be a JSON array of $$result entries, each with every field the runner reads and its reason in \"comment\"" >&2; exit 1; }; \
	done
	rm -rf conformance/tls conformance/results
	mkdir -p conformance/tls conformance/results
	openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=pulsar \
		-addext subjectAltName=DNS:pulsar \
		-keyout conformance/tls/key.pem -out conformance/tls/cert.pem 2>/dev/null
	@set -e; \
	CONFORMANCE_USER="$$(id -u):$$(id -g)"; PULSAR_SECRET="$$(openssl rand -base64 32)"; \
	export CONFORMANCE_USER PULSAR_SECRET; \
	$(CONFORMANCE_COMPOSE) down --volumes --remove-orphans --timeout 0; \
	trap 'set +e; trap "" INT TERM; \
		for s in $$($(CONFORMANCE_COMPOSE) config --services | grep -vx runner); do \
			$(CONFORMANCE_COMPOSE) logs --no-color "$$s" > "conformance/results/$$s.log" 2>&1; \
		done; \
		$(CONFORMANCE_COMPOSE) down --volumes --remove-orphans --timeout 0' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(CONFORMANCE_COMPOSE) build; \
	$(CONFORMANCE_COMPOSE) run --rm runner

# The examples' Go tests against pulsar, in the Docker Compose stack of
# examples/compose.yaml, which publishes pulsar on the host's loopback
# interface at EXAMPLES_ISSUER. Every run starts from nothing, with a
# PULSAR_SECRET generated for it and never committed. The tests reach
# pulsar by that URL, and rotate its signing key with `pulsar keys rotate`
# run in its container, as an operator would. If they fail, every service's
# log is printed; however the run ends, the stack and its volumes are
# removed, as for make conformance.
# Needs Docker with Compose v2, openssl and Go; inside the sandbox it cannot
# reach Docker (docs/harness.md).
EXAMPLES_COMPOSE := docker compose --file examples/compose.yaml
EXAMPLES_ISSUER := http://127.0.0.1:9080

examples: ## Run the examples' tests against pulsar in Docker Compose; needs Docker
	@set -e; \
	PULSAR_SECRET="$$(openssl rand -base64 32)"; export PULSAR_SECRET; \
	$(EXAMPLES_COMPOSE) down --volumes --remove-orphans --timeout 0; \
	trap 'status=$$?; set +e; trap "" INT TERM; \
		[ "$$status" -eq 0 ] || $(EXAMPLES_COMPOSE) logs --no-color; \
		$(EXAMPLES_COMPOSE) down --volumes --remove-orphans --timeout 0' EXIT; \
	trap 'exit 130' INT; trap 'exit 143' TERM; \
	$(EXAMPLES_COMPOSE) up --build --detach; \
	PULSAR_EXAMPLES_ISSUER=$(EXAMPLES_ISSUER) \
	PULSAR_EXAMPLES_ROTATE="docker compose --file '$(CURDIR)/examples/compose.yaml' exec -T pulsar /pulsar keys rotate" \
		$(GO) -C $(EXAMPLES) test -race -count=1 -timeout 10m ./...

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
