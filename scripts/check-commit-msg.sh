#!/usr/bin/env bash
#
# Checks a commit message header against Conventional Commits 1.0.0: a known
# type, an optional scope, an optional "!", a description that does not open
# with a capitalized word (an acronym such as JWKS is fine) and has no
# trailing period, and at most 72 characters. Used by the commit-msg hook
# and by CI, so the rule has one definition.

set -euo pipefail

readonly message_file="${1:?usage: check-commit-msg.sh <path-to-commit-message>}"
readonly max_header=72
readonly types='build|chore|ci|docs|feat|fix|perf|refactor|revert|style|test'

# The first line that is neither a comment nor blank.
header=$(awk '!/^#/ && NF { print; exit }' "${message_file}")

if [[ -z ${header} ]]; then
	echo "The commit message is empty." >&2
	exit 1
fi

# Git writes these itself.
case "${header}" in
Merge\ * | Revert\ * | fixup!\ * | squash!\ * | amend!\ *) exit 0 ;;
esac

fail() {
	{
		echo "$1"
		echo
		echo "  got: ${header}"
		echo
		echo "Expected: <type>[(scope)][!]: <description>"
		echo "Types:    ${types//|/, }"
	} >&2
	exit 1
}

if ! [[ ${header} =~ ^(${types})(\([a-z0-9./_-]+\))?!?:\ (.+)$ ]]; then
	fail "The header does not follow Conventional Commits."
fi
description=${BASH_REMATCH[3]}

if [[ ${description} =~ ^[A-Z]([^A-Z0-9]|$) ]]; then
	fail "The description starts with a capitalized word."
fi
if [[ ${description} == *. ]]; then
	fail "The description ends with a period."
fi
if ((${#header} > max_header)); then
	fail "The header is ${#header} characters; the limit is ${max_header}."
fi
