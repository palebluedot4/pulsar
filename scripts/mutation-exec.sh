#!/usr/bin/env bash
#
# Tests one mutant for go-mutesting, which runs it with the mutant's file in
# MUTATE_CHANGED, the file it replaces in MUTATE_ORIGINAL and its package in
# MUTATE_PACKAGE (docs/mutation-testing.md). Unlike go-mutesting's own exec,
# it runs every package's tests, not only the mutated package's:
# internal/oidc has no tests of its own, internal/server tests it over HTTP.
# Packages the mutant cannot reach keep their cached results.
#
# Exit status, as go-mutesting reads it: 0 the tests failed, so the mutant
# is killed; 1 they passed, so it lived; 2 it did not compile, so it is
# skipped. Two more, which go-mutesting counts as errors and this script
# names on its output, are neither killed nor lived: 3 a test timed out, 4
# a test found PostgreSQL out of connections (SQLSTATE 53300), because
# something else used the test database meanwhile.
#
# The mutant is written over the source file and the original put back on
# exit, so make mutation runs it in a working tree of its own.
# MUTATION_TEST_TIMEOUT bounds each run of a package's tests.

set -uo pipefail

: "${MUTATE_CHANGED:?}" "${MUTATE_ORIGINAL:?}" "${MUTATE_PACKAGE:?}"

backup="$MUTATE_ORIGINAL.mutation-original"
mv "$MUTATE_ORIGINAL" "$backup"
trap 'mv "$backup" "$MUTATE_ORIGINAL"' EXIT
cp "$MUTATE_CHANGED" "$MUTATE_ORIGINAL"

diff=$(diff -u --label original --label mutant "$backup" "$MUTATE_ORIGINAL")

if ! go build "$MUTATE_PACKAGE" 2>/dev/null; then
	exit 2
fi

output=$(go test -vet=off -timeout "${MUTATION_TEST_TIMEOUT:-90s}" ./... 2>&1)
status=$?

if [[ $status -eq 0 ]]; then
	printf 'LIVED %s\n%s\n' "$MUTATE_ORIGINAL" "$diff"
	exit 1
fi
if grep -q 'SQLSTATE 53300' <<<"$output"; then
	printf 'DATABASE FULL %s\n%s\n' "$MUTATE_ORIGINAL" "$diff"
	exit 4
fi
if grep -q '^panic: test timed out' <<<"$output"; then
	printf 'TIMED OUT %s\n%s\n' "$MUTATE_ORIGINAL" "$diff"
	exit 3
fi
exit 0
