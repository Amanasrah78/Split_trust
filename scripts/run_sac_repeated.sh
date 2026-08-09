#!/usr/bin/env bash
set -euo pipefail

requests=2000
warmup=100

orders=(
  "1 5 10 25 50 100"
  "100 50 25 10 5 1"
  "10 25 50 100 1 5"
  "50 10 1 100 25 5"
  "25 1 100 5 50 10"
)

: > results/sac-trial-order.txt

for run_index in 1 2 3 4 5
do
  order="${orders[$((run_index - 1))]}"

  for concurrency in $order
  do
    run_id="run${run_index}"

    printf 'run=%s concurrency=%s started=%s\n' \
      "$run_id" \
      "$concurrency" \
      "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" \
      | tee -a results/sac-trial-order.txt

    docker compose restart \
      ledger-adapter sac gateway-b gateway-a

    docker compose up -d --wait --wait-timeout 60

    docker compose run --rm loadgen \
      python -m app.benchmark \
      --mode sac \
      --warmup "$warmup" \
      --requests "$requests" \
      --concurrency "$concurrency" \
      --timeout 60 \
      --run-id "$run_id"
  done
done
