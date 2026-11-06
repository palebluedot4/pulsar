#!/bin/sh
# Runs the Config OP plan against pulsar through the suite's CI runner, once
# pulsar reports ready, and exports the results to /results. The runner
# waits for the suite by itself, and exits non-zero when a module fails to
# finish, a condition fails or warns without an entry in the expected files,
# or an entry there matches nothing.
set -eu

ready_url=https://pulsar:9443/readyz

# pulsar's certificate is self-signed for this run, so it is not verified.
tries=0
until python3 -c '
import ssl, sys, urllib.request
urllib.request.urlopen(sys.argv[1], context=ssl._create_unverified_context(), timeout=2)
' "$ready_url" 2>/dev/null; do
	tries=$((tries + 1))
	if [ "$tries" -ge 60 ]; then
		echo "run.sh: pulsar did not become ready at $ready_url within 60 seconds" >&2
		exit 1
	fi
	sleep 1
done

exec python3 /suite/run-test-plan.py \
	--verbose \
	--expected-failures-file '/conformance/expected-failures.json|/conformance/expected-warnings.json' \
	--export-dir /results \
	oidcc-config-certification-test-plan /conformance/config-op.json
