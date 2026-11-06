#!/bin/sh
# Runs the Config OP and Basic OP plans against pulsar through the suite's
# CI runner, once pulsar reports ready, and exports the results to /results.
# The runner waits for the suite by itself, and exits non-zero when a module
# fails to finish, a condition fails or warns without an entry in the
# expected files, a module is skipped without one, or an entry there
# matches nothing. Both configurations share an alias, so the plans run one
# after the other.
set -eu

ready_url=https://pulsar:9443/readyz

wait_seconds=60

# pulsar's certificate is self-signed for this run, so it is not verified.
deadline=$(($(date +%s) + wait_seconds))
until python3 -c '
import ssl, sys, urllib.request
urllib.request.urlopen(sys.argv[1], context=ssl._create_unverified_context(), timeout=2)
' "$ready_url" 2>/dev/null; do
	if [ "$(date +%s)" -ge "$deadline" ]; then
		echo "run.sh: pulsar was not ready at $ready_url after $wait_seconds seconds; see conformance/results/pulsar.log" >&2
		exit 1
	fi
	sleep 1
done

exec python3 /suite/run-test-plan.py \
	--verbose \
	--expected-failures-file '/conformance/expected-failures.json|/conformance/expected-warnings.json' \
	--expected-skips-file /conformance/expected-skips.json \
	--export-dir /results \
	oidcc-config-certification-test-plan /conformance/config-op.json \
	'oidcc-basic-certification-test-plan[server_metadata=discovery][client_registration=static_client]' /conformance/config-basic.json
