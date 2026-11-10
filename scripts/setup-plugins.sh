#!/usr/bin/env bash
#
# Adds the marketplaces .claude/settings.json declares and installs, at
# project scope, the plugins it enables. Run by make setup from the
# repository's root. Without an install record, right-sizing did not load
# at session start (#68); without the marketplaces, which the claude plugin
# commands do not clone, every install failed on a fresh machine (#92). The
# evidence for each step is in docs/research/code-review-tools.md.

set -euo pipefail

readonly settings=.claude/settings.json
readonly name_re='^[A-Za-z0-9][A-Za-z0-9._-]*$'
readonly repo_re='^[A-Za-z0-9][A-Za-z0-9._-]*/[A-Za-z0-9._-]+$'

# Each command rewrites the settings in another order, which Prettier
# rejects, and adding a marketplace drops its autoUpdate, so the file is put
# back byte for byte, even when a command fails.
saved=$(mktemp "${TMPDIR:-/tmp}/settings.json.XXXXXX")
readonly saved
trap 'cp "${saved}" "${settings}"; rm -f "${saved}"' EXIT
cp "${settings}" "${saved}"

# An install refreshes the marketplace it installs from, whatever its
# autoUpdate says; with Claude Code 2.1.319, of DISABLE_AUTOUPDATER,
# DISABLE_UPDATES and this variable, only this one stops it. A marketplace
# with autoUpdate on is updated explicitly instead, below.
export CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1

# One line per marketplace: its name, its owner/repo and whether autoUpdate
# is on. Only a GitHub source named by owner/repo alone can be added as
# declared; a ref, for one, would be dropped.
marketplaces=$(jq -r --arg name_re "${name_re}" --arg repo_re "${repo_re}" '
	(.extraKnownMarketplaces // {}) | to_entries[]
	| if (.key | test($name_re)) and .value.source.source == "github"
		and (.value.source | keys) == ["repo", "source"]
		and (.value.source.repo | test($repo_re))
	then "\(.key) \(.value.source.repo) \(.value.autoUpdate == true)"
	else error("\(.key): only a GitHub marketplace named by owner/repo alone can be added")
	end' "${settings}")
plugins=$(jq -r --arg name_re "${name_re}" '
	(.enabledPlugins // {}) | to_entries[] | select(.value) | .key
	| if (split("@") | length == 2 and all(test($name_re))) then .
	else error("\(.): not a plugin@marketplace name")
	end' "${settings}")
readonly marketplaces plugins

# The loops read their lists from standard input, so each claude command
# reads /dev/null instead of the rest of the list.
frozen=()
while read -r name repo auto_update; do
	[[ -n ${name} ]] || continue
	echo "claude plugin marketplace add ${repo} --scope project"
	if ! out=$(claude plugin marketplace add "${repo}" --scope project --json </dev/null); then
		printf '%s\n' "${out}"
		exit 1
	fi
	result=$(tail -n 1 <<<"${out}")
	jq -r .message <<<"${result}"
	added=$(jq -r .marketplace <<<"${result}")
	if [[ ${added} != "${name}" ]]; then
		echo "setup-plugins: ${repo} is declared as ${name} but was added as ${added}" >&2
		exit 1
	fi
	if [[ ${auto_update} == true ]]; then
		echo "claude plugin marketplace update ${name}"
		claude plugin marketplace update "${name}" </dev/null
	else
		frozen+=("${name}")
	fi
done <<<"${marketplaces}"

# A digest of every file in each frozen marketplace's copy, so that an
# install that moves one fails here instead of passing unnoticed, should a
# later release of Claude Code stop honoring the variable above. Bash clears
# set -e in a command substitution, so every step checks its own status.
frozen_state() {
	local name location listing
	listing=$(claude plugin marketplace list --json </dev/null) || return 1
	for name in ${frozen[@]+"${frozen[@]}"}; do
		location=$(jq -r --arg name "${name}" '.[] | select(.name == $name) | .installLocation' <<<"${listing}") || return 1
		if [[ ! -d ${location} ]]; then
			echo "setup-plugins: no copy of marketplace ${name} at '${location}'" >&2
			return 1
		fi
		printf '%s ' "${name}"
		(cd "${location}" && find . -name .git -prune -o -type f -print0 | LC_ALL=C sort -z | xargs -0 shasum) | shasum || return 1
	done
}

before=$(frozen_state)
readonly before
while read -r plugin; do
	[[ -n ${plugin} ]] || continue
	echo "claude plugin install ${plugin} --scope project"
	claude plugin install "${plugin}" --scope project </dev/null
done <<<"${plugins}"

after=$(frozen_state)
readonly after
if [[ ${after} != "${before}" ]]; then
	echo "setup-plugins: an install changed a marketplace with autoUpdate off: ${frozen[*]}" >&2
	exit 1
fi
