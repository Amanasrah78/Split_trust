#!/usr/bin/env bash
set -euo pipefail

requests=100
concurrency=10
timeout=30

: > results/revocation-trial-order.txt

for run_index in 1 2 3 4 5
do
  run_id="run${run_index}"

  printf 'run=%s concurrency=%s requests=%s started=%s\n' \
    "$run_id" \
    "$concurrency" \
    "$requests" \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    | tee -a results/revocation-trial-order.txt

  # Clear in-memory experiment state.
  # Gateway B is restarted before Gateway A because B regenerates
  # its KEM key at startup and A must fetch the new public key.
  docker compose restart ledger-adapter sac gateway-b

  docker compose up -d --wait --wait-timeout 60 \
    ledger-adapter sac gateway-b

  docker compose restart gateway-a

  docker compose up -d --wait --wait-timeout 60 \
    gateway-a

  docker compose run --rm loadgen \
    python -m app.benchmark \
    --mode revocation \
    --requests "$requests" \
    --concurrency "$concurrency" \
    --warmup 0 \
    --timeout "$timeout" \
    --run-id "$run_id"

  printf 'run=%s completed=%s\n' \
    "$run_id" \
    "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
    | tee -a results/revocation-trial-order.txt
done