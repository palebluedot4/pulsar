#!/usr/bin/env bash
#
# PostToolUse: formats the file Claude just wrote, and only that file, so
# formatting never reaches the gate or a reviewer. Go goes through
# golangci-lint's formatters; Markdown, YAML and JSON through Prettier, and
# Markdown then through markdownlint's fixes; shell scripts through shfmt.
# Anything that cannot be fixed automatically is reported back to Claude.

set -euo pipefail

if ! command -v jq >/dev/null; then
	echo "jq is not installed; the format hook cannot read which file was edited." >&2
	exit 2
fi
file=$(jq -r '.tool_input.file_path // empty')
[[ -f ${file} && ${file} == "${CLAUDE_PROJECT_DIR}"/* ]] || exit 0
cd "${CLAUDE_PROJECT_DIR}"

run() {
	local out
	if [[ ! -x $1 ]] && ! command -v "$1" >/dev/null; then
		echo "$1 is not installed; the maintainer needs to run \`make setup\` outside the sandbox." >&2
		exit 2
	fi
	if ! out=$("$@" 2>&1); then
		echo "$* reported problems in ${file}:" >&2
		echo "${out}" >&2
		exit 2
	fi
}

case "${file}" in
*.go)
	run "$(make -s print-GOLANGCI_LINT)" fmt "${file}"
	;;
*.md)
	run node_modules/.bin/prettier --write --log-level warn "${file}"
	run node_modules/.bin/markdownlint-cli2 --no-globs --fix "${file}"
	;;
*.yml | *.yaml | *.json | *.jsonc)
	run node_modules/.bin/prettier --write --log-level warn --ignore-unknown "${file}"
	;;
*.sh | */.githooks/*)
	run go tool -modfile=tools/go.mod shfmt -w "${file}"
	;;
esac
