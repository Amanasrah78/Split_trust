# Split-Trust Docker Testbed

This testbed implements SAC-inclusive cross-domain authorization and post-quantum session establishment.

Reproducibility revision: `5e72b86` (`align-protocol-tamarin`).

## Services

- `gateway-a`: initiates authorization and ML-KEM encapsulation.
- `gateway-b`: verifies SAC provisioning and performs ML-KEM decapsulation.
- `sac`: evaluates policy, signs session context, and provisions authorization inputs.
- `ledger-adapter`: processes commitments after session usability.
- `loadgen`: runs E2E, SAC concurrency, overload, and logical multi-domain scalability experiments.

## Host ports

| Service | URL |
|---|---|
| Gateway A | http://localhost:8080 |
| SAC | http://localhost:8081 |
| Gateway B | http://localhost:8082 |
| Ledger adapter | http://localhost:8083 |

## Protocol flow

1. Gateway A generates a nonce.
2. The E2E timer starts immediately before Gateway A sends the SAC request.
3. The SAC evaluates policy and constructs the session context and capability.
4. The SAC generates `S_SAC` and `S_auth`.
5. The SAC signs and encrypts authorization material for both gateways.
6. Both gateways verify the authorization package and cached ledger epoch.
7. Gateway A performs ML-KEM-768 encapsulation.
8. Gateway B performs ML-KEM-768 decapsulation.
9. Both gateways derive the session key with HKDF-SHA-256.
10. Gateway B generates an HMAC-SHA-256 confirmation.
11. Gateway A verifies the confirmation and stops the E2E timer.
12. The session becomes usable.
13. Gateway A submits the session commitment asynchronously.

## Timing definitions

### SAC-inclusive E2E latency

`e2e_ns` starts immediately before Gateway A sends the SAC request and ends after successful key-confirmation verification.

It includes SAC interaction, Docker-network transport, authorization verification, ML-KEM, HKDF, MAC confirmation, serialization, scheduling, and gateway processing.

It excludes ledger enqueue, ledger finality, periodic revocation lookup, and later data-plane traffic.

### Gateway cryptographic processing

`gateway_crypto_full_ns` is cumulative processing across both gateways. It includes authorization verification, ML-KEM, HKDF, and MAC operations.

It is not an E2E wall-clock interval.

### Ledger latency

`ledger_enqueue_ns` begins after the session becomes usable. `ledger_final_ns` is measured independently by the ledger adapter.

The baseline `compose.yaml` intentionally uses `LEDGER_MODE=simulated` so
Experiment A and the delay matrix remain reproducible without credentials.
This is not the only available backend.

`LEDGER_MODE=iota` adds an asynchronous current-IOTA testnet backend. It uses
the included Move event package, records transaction submission and
checkpoint-confirmation measurements, and remains outside `e2e_ns`. See
[`docs/experiments-b-c.md`](docs/experiments-b-c.md) for funded testnet setup.

Experiment C was exercised successfully against the current IOTA testnet after
publishing the included package. Use `compose.iota.yaml` to select that live
backend; it changes the ledger adapter to `LEDGER_MODE=iota` while leaving the
baseline compose file unchanged.

## Repeated concurrency-1 results

Five trials were run. Each contained 1,000 measured sessions after 100 warm-ups.

| Metric | Mean and 95% CI | p95 and 95% CI |
|---|---:|---:|
| SAC-inclusive E2E | 2.1684 ± 0.0939 ms | 2.8499 ± 0.3801 ms |
| Authorization path | 1.3773 ± 0.0636 ms | 1.8394 ± 0.2661 ms |
| SAC processing | 0.8019 ± 0.0392 ms | 1.0846 ± 0.1570 ms |
| Gateway cryptographic processing | 0.3223 ± 0.0137 ms | 0.4163 ± 0.0452 ms |
| Gateway handshake round trip | 0.6074 ± 0.0211 ms | 0.7889 ± 0.0732 ms |
| Post-usability ledger enqueue | 0.5629 ± 0.0238 ms | 0.7265 ± 0.0961 ms |

## SAC scalability

Each level used five trials of 2,000 requests after 100 warm-ups.

| Concurrency | Throughput, authorizations/s | Client mean | Client p95 |
|---:|---:|---:|---:|
| 1 | 810.10 ± 12.82 | 1.220 ± 0.020 ms | 1.586 ± 0.065 ms |
| 5 | 1365.14 ± 17.15 | 3.600 ± 0.045 ms | 5.799 ± 0.190 ms |
| 10 | 1134.59 ± 27.00 | 8.738 ± 0.207 ms | 19.615 ± 0.428 ms |
| 25 | 825.82 ± 13.72 | 29.798 ± 0.390 ms | 72.803 ± 2.508 ms |
| 50 | 723.39 ± 174.59 | 69.984 ± 17.469 ms | 195.916 ± 71.451 ms |
| 100 | 345.37 ± 26.19 | 284.096 ± 20.881 ms | 981.655 ± 144.247 ms |

The highest observed throughput was `1365.14 ± 17.15 authorizations/s` at concurrency 5. The saturation knee lies between concurrency 5 and 10.

## Logical multi-domain scalability

The logical domain-registry experiment varies the number of registered
administrative domains as `N = {2, 5, 10, 25, 50}` while fixing authorization
concurrency at `C = 10`. For each `N`, SAC and Gateway B are initialized with
the corresponding gateway-DID registry and an indexed policy table containing
all `N(N-1)` ordered source-destination domain relationships.

Each configuration uses five independent trials, with 100 warm-up requests
followed by 1,000 measured authorization requests per trial. Across the full
campaign, 25,000/25,000 measured requests completed successfully with zero
failures.

| Domains N | Ordered policies | Throughput, auth/s | Client mean | Client p95 | Authorization-path mean | Authorization-path p95 |
|---:|---:|---:|---:|---:|---:|---:|
| 2 | 2 | 1038.92 ± 64.95 | 9.54 ± 0.59 ms | 21.92 ± 2.32 ms | 7.55 ± 0.52 ms | 18.83 ± 1.99 ms |
| 5 | 20 | 1095.22 ± 46.70 | 9.03 ± 0.37 ms | 19.40 ± 0.58 ms | 7.21 ± 0.20 ms | 17.02 ± 0.38 ms |
| 10 | 90 | 1062.00 ± 93.36 | 9.36 ± 0.83 ms | 20.87 ± 2.69 ms | 7.57 ± 0.59 ms | 18.61 ± 2.43 ms |
| 25 | 600 | 1002.57 ± 67.34 | 9.88 ± 0.65 ms | 21.74 ± 1.40 ms | 7.83 ± 0.59 ms | 18.92 ± 1.59 ms |
| 50 | 2450 | 983.38 ± 61.02 | 10.08 ± 0.61 ms | 22.37 ± 1.31 ms | 8.05 ± 0.63 ms | 19.89 ± 1.55 ms |

Values are trial means ± 95% confidence intervals.

From `N=2` to `N=50`, throughput decreased by 5.35%, client mean latency
increased by 5.66%, client p95 increased by 2.05%, and authorization-path mean
latency increased by 6.67%. Direct two-sided permutation comparisons between
the `N=2` and `N=50` trials did not detect a significant endpoint difference
for the reported throughput or latency metrics (`p > 0.1` in each case).

This experiment measures logical registry and indexed authorization-policy
scaling. It does not represent 50 physically independent or geographically
distributed gateway deployments.

## Reproduction commands

Build and start:

    docker compose up -d --build
    docker compose ps

Run tests:

    docker compose run --rm sac python -m pytest -q /app/tests

Run E2E trials:

    ./scripts/run_e2e_repeated.sh
    python3 scripts/aggregate_repeated.py e2e
    python3 scripts/aggregate_breakdown.py

Run SAC trials:

    ./scripts/run_sac_repeated.sh
    python3 scripts/aggregate_repeated.py sac

Run the logical multi-domain scalability campaign:

    ./scripts/run_multidomain_campaign.sh

The campaign varies `N` over 5, 10, 25, and 50 logical domains. The script
uses `REGISTERED_GATEWAY_DIDS`, recreates SAC and Gateway B when `N` changes,
restarts them between trials, and runs five trials per configuration at
concurrency 10. The `--domains` load-generator option is available for
individual SAC-mode domain-scaling runs.

Run the controlled network-delay matrix (Experiment B):

    ./scripts/run_delay_matrix.sh

Run one 5 ms smoke trial:

    DELAYS=5 TRIALS=1 WARMUP=2 REQUESTS=10 ./scripts/run_delay_matrix.sh

Run with the live IOTA test-network backend (Experiment C, after setup):

    docker compose -f compose.yaml -f compose.iota.yaml up -d --build --wait

Run the SAC outage/recovery availability experiment:

    ./scripts/run_sac_outage_recovery.sh

This establishes one session before stopping the SAC, verifies that new
sessions fail closed while the SAC is unavailable, and verifies that new
sessions recover after the SAC is restarted. The output is written to
`results/sac-outage-recovery-summary.json`. The current API does not expose a
data-plane operation after establishment, so this experiment does not measure
application traffic on an already established session.

## Result files

Benchmark commands write generated output under `results/`. Raw experiment
logs and JSONL datasets are generated locally and are not all committed to the
repository. The implementation and reproduction scripts are versioned.

- `results/environment.txt`
- `results/experiment-manifest.json`
- `results/e2e-repeated-aggregate.csv`
- `results/e2e-c1-component-aggregate.csv`
- `results/sac-repeated-aggregate.csv`
- Per-request JSONL datasets.
- Per-trial JSON summaries.
- `results/public-baseline-comparison.md` documents public PQ-handshake and
  IIoT identity implementations that can be used as scoped comparison
  references.

## Interpretation constraints

1. `2.1684 ms` is the new SAC-inclusive E2E latency.
2. `0.3223 ms` is gateway cryptographic processing, not E2E latency.
3. Historical `0.62 ms` and Shimmer results came from a different implementation and environment.
4. The Docker bridge represents same-host communication.
5. Each service uses one application worker.
6. Client latency is authoritative for SAC scalability because it includes queueing.
7. The cached ledger epoch is loaded before the E2E timer begins.
8. Simulated ledger finality must not be presented as a live-IOTA measurement.
9. The `N={2,5,10,25,50}` experiment measures logical registry and policy-state
   scaling, not physically or geographically independent gateway deployments.

## Manuscript alignment

A requirement to confirm or retrieve a new per-session ledger commitment before key derivation would put the ledger on the critical path and contradict the off-path claim.

`R_IOTA` is public freshness context, not secret entropy. Session secrecy must rely on the ML-KEM shared secret and confidential SAC inputs.
