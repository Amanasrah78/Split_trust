# Experiments B and C

## Experiment B: controlled one-way delay

`compose.delay.yaml` leaves `compose.yaml` unchanged. It inserts three Linux
TCP relay containers on the measured links: Gateway A to SAC, SAC to Gateway B,
and Gateway A to Gateway B. Each relay applies `tc netem` to its egress
interface, so request and response packets each receive the selected one-way
delay. Ledger traffic does not use a relay and remains after session usability.

Run the full matrix:

```sh
./scripts/run_delay_matrix.sh
```

The runner uses the compose project's normal name, replaces any running
baseline containers for the duration of the experiment, and removes the delay
stack when it exits. Restart the baseline afterward with `docker compose up
-d` if needed.

The defaults are 100 warm-ups, 1,000 measured sessions, concurrency one, five
independent trials, and one-way delays of 5, 10, 25, and 50 ms. For a quick
5 ms validation:

```sh
DELAYS=5 TRIALS=1 WARMUP=2 REQUESTS=10 ./scripts/run_delay_matrix.sh
```

Per-request JSONL and per-trial JSON summaries are written to `results/`.
`results/delay-matrix-aggregate.csv` reports the across-trial E2E mean and p95,
with Student-t 95% confidence intervals. A one-trial smoke test reports a zero
confidence-interval width and is not a publishable experiment. Nonstandard
request counts use a separate file such as
`results/delay-matrix-n10-aggregate.csv`, so smoke data cannot contaminate the
1,000-session aggregate.

The proxy containers require Docker's `NET_ADMIN` capability. The capability is
limited to those containers and does not configure the macOS host.

## Experiment C: live IOTA test network

The default `LEDGER_MODE=simulated` behavior is unchanged. Live mode uses the
current IOTA Move network rather than the obsolete Shimmer tagged-data API. The
included Move package emits a `CommitmentSubmitted` event containing a fixed
16-byte namespace tag, 32-byte commitment, and 32-byte session identifier.

External setup is intentionally explicit because it controls a funded signing
key:

1. Install a current IOTA CLI and initialize a testnet client configuration.
2. Fund its active testnet address.
3. Publish `iota/commitment-registry` and record the package ID.
4. Provide a Linux IOTA CLI binary for the ledger container and the initialized
   client configuration directory. Do not commit either the keystore or seed.
5. Set `IOTA_PACKAGE_ID`, `IOTA_CLI_BINARY`, and
   `IOTA_CLIENT_CONFIG_DIR` in `.env`.

Build and publish with the same CLI version that will submit transactions:

```sh
iota move build --path iota/commitment-registry
iota client publish iota/commitment-registry \
  --gas-budget 100000000 --json
```

Start the testbed in live mode:

```sh
docker compose -f compose.yaml -f compose.iota.yaml up -d --build --wait
```

Exercise a session and inspect its asynchronous ledger job:

```sh
curl -sS -X POST http://localhost:8080/sessions \
  -H 'content-type: application/json' \
  -d '{"device_handle":"actuator-c","action":"operate"}'
curl -sS http://localhost:8083/commitments/JOB_ID
```

The status resource records submission latency, transaction digest, polling
latency, checkpoint-backed lookup status, total finality latency, and failure or
timeout details. Submission still starts after key confirmation, so neither CLI
execution nor confirmation polling is part of `e2e_ns`.

The live backend deliberately uses one worker by default. A single funded IOTA
address can otherwise attempt concurrent transactions against the same gas
coin. Increase `IOTA_LEDGER_WORKER_COUNT` only after provisioning a signing
strategy that supports concurrent gas inputs.
