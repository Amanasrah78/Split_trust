#!/usr/bin/env bash
set -euo pipefail

requests="${REQUESTS:-1000}"
warmup="${WARMUP:-100}"
trials="${TRIALS:-5}"
delays="${DELAYS:-5 10 25 50}"
timeout="${TIMEOUT_SECONDS:-120}"
compose=(docker compose -f compose.yaml -f compose.delay.yaml)

mkdir -p results
manifest="results/delay-matrix-trial-order.txt"
: > "$manifest"

cleanup() {
  "${compose[@]}" down --remove-orphans >/dev/null 2>&1 || true
}
trap cleanup EXIT

for delay_ms in $delays; do
  case "$delay_ms" in
    5|10|25|50) ;;
    *)
      echo "Unsupported delay ${delay_ms}; use 5, 10, 25, or 50 ms" >&2
      exit 2
      ;;
  esac

  export DELAY_MS="$delay_ms"
  "${compose[@]}" down --remove-orphans
  "${compose[@]}" up -d --build --wait --wait-timeout 120

  for run_index in $(seq 1 "$trials"); do
    run_id="delay-${delay_ms}ms-run${run_index}"
    printf 'delay_ms=%s run=%s requests=%s warmup=%s started=%s\n' \
      "$delay_ms" "$run_index" "$requests" "$warmup" \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" | tee -a "$manifest"

    # Reset all stateful application processes between independent trials.
    "${compose[@]}" restart ledger-adapter sac gateway-b gateway-a
    "${compose[@]}" up -d --wait --wait-timeout 120

    "${compose[@]}" run --rm loadgen \
      python -m app.benchmark \
      --mode e2e \
      --warmup "$warmup" \
      --requests "$requests" \
      --concurrency 1 \
      --timeout "$timeout" \
      --run-id "$run_id"
  done
done

python3 scripts/aggregate_delay_matrix.py --requests "$requests"
