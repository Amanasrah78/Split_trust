#!/usr/bin/env bash
set -euo pipefail

# SAC availability experiment.
# The experiment verifies three properties:
#   1. a session can be established before an SAC outage;
#   2. new sessions fail closed while the SAC is unavailable;
#   3. new sessions recover after the SAC is restarted.
# Existing-session key continuity is a protocol property and is not re-
# authorized by the /sessions endpoint; this runner therefore does not claim
# to measure data-plane traffic during the outage.

requests="${SAC_OUTAGE_REQUESTS:-20}"
warmup="${SAC_OUTAGE_WARMUP:-5}"
timeout="${SAC_OUTAGE_TIMEOUT:-10}"
output_directory="${SAC_OUTAGE_OUTPUT_DIRECTORY:-results}"

mkdir -p "$output_directory"

run_loadgen() {
  local run_id="$1"
  local run_warmup="$2"
  local run_requests="$3"

  docker compose run --rm --no-deps loadgen \
    python -m app.benchmark \
    --mode e2e \
    --warmup "$run_warmup" \
    --requests "$run_requests" \
    --concurrency 1 \
    --timeout "$timeout" \
    --run-id "$run_id" \
    --output-directory /results
}

echo "Starting the complete testbed."
docker compose up -d --wait --wait-timeout 60

echo "Measuring a session before the outage."
run_loadgen sac-outage-before "$warmup" 1

echo "Stopping SAC and testing fail-closed behavior for new sessions."
docker compose stop sac
run_loadgen sac-outage-during 0 "$requests" || true

echo "Restarting SAC and testing recovery."
docker compose start sac
docker compose up -d --wait --wait-timeout 60 sac
run_loadgen sac-outage-after "$warmup" "$requests"

python3 - "$output_directory" "$requests" <<'PY'
import json
import sys
from pathlib import Path

output = Path(sys.argv[1])
expected_during = int(sys.argv[2])

def read_summary(run_id: str) -> dict:
    path = output / f"e2e-c1-n{expected_during if run_id == 'sac-outage-during' else (1 if run_id == 'sac-outage-before' else expected_during)}-{run_id}-summary.json"
    if not path.exists():
        matches = sorted(output.glob(f"e2e-c1-n*-{run_id}-summary.json"))
        if not matches:
            raise SystemExit(f"Missing summary for {run_id}")
        path = matches[-1]
    return json.loads(path.read_text(encoding="utf-8"))

before = read_summary("sac-outage-before")
during = read_summary("sac-outage-during")
after = read_summary("sac-outage-after")

result = {
    "experiment": "sac-outage-recovery",
    "before_outage": {
        "successes": before.get("successes", 0),
        "failures": before.get("failures", 0),
    },
    "during_outage": {
        "successes": during.get("successes", 0),
        "failures": during.get("failures", 0),
    },
    "after_recovery": {
        "successes": after.get("successes", 0),
        "failures": after.get("failures", 0),
    },
    "expected_behavior": {
        "pre_outage_session_established": before.get("successes", 0) == 1,
        "new_sessions_fail_closed_during_outage": during.get("successes", 0) == 0 and during.get("failures", 0) == expected_during,
        "new_sessions_recover_after_restart": after.get("successes", 0) == expected_during,
    },
}

path = output / "sac-outage-recovery-summary.json"
path.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps(result, indent=2, sort_keys=True))

if not all(result["expected_behavior"].values()):
    raise SystemExit("SAC outage experiment did not meet all expected behaviors")
PY

echo "SAC outage/recovery experiment completed successfully."
