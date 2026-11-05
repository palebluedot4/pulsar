#!/usr/bin/env bash
#
# Stop: runs `make check` before Claude may finish.
#
# The result is keyed to the content of the working tree, including untracked
# files. A tree that already passed is not checked again, and a failure is
# reported only once per tree: if Claude stops again without changing
# anything, it is let go rather than trapped in a loop, and the failure stays
# in the transcript for the human. Any edit makes the next stop check again.
#
# If the tree cannot be fingerprinted, nothing is cached: the check always
# runs, and Claude's own loop guard (stop_hook_active) is what lets it go.

set -uo pipefail

input=$(cat)
cd "${CLAUDE_PROJECT_DIR}" || exit 0
git_dir=$(git rev-parse --absolute-git-dir) || exit 0
state_file="${git_dir}/pulsar-stop-check"

# Hash the working tree through a throwaway index beside the real one, which
# is left untouched.
index="${git_dir}/pulsar-stop-check.index"
tree=""
if cp "${git_dir}/index" "${index}" 2>/dev/null &&
	GIT_INDEX_FILE=${index} git add -A >/dev/null 2>&1; then
	tree=$(GIT_INDEX_FILE=${index} git write-tree 2>/dev/null) || tree=""
fi
rm -f "${index}"

if [[ -n ${tree} ]]; then
	previous=$(cat "${state_file}" 2>/dev/null || true)
	if [[ ${previous} == "pass ${tree}" || ${previous} == "fail ${tree}" ]]; then
		exit 0
	fi
elif [[ $(jq -r '.stop_hook_active // false' <<<"${input}") == true ]]; then
	exit 0
fi

if out=$(make check 2>&1); then
	[[ -n ${tree} ]] && echo "pass ${tree}" >"${state_file}"
	exit 0
fi

[[ -n ${tree} ]] && echo "fail ${tree}" >"${state_file}"
{
	echo "make check failed. Fix the cause, or say why it cannot be fixed; this failure is reported once for this tree."
	echo
	echo "${out}" | tail -n 80
} >&2
exit 2
