# Split-Trust Docker Testbed

This testbed implements SAC-inclusive cross-domain authorization and post-quantum session establishment.

## Services

- `gateway-a`: initiates authorization and ML-KEM encapsulation.
- `gateway-b`: verifies SAC provisioning and performs ML-KEM decapsulation.
- `sac`: evaluates policy, signs session context, and provisions authorization inputs.
- `ledger-adapter`: processes commitments after session usability.
- `loadgen`: runs E2E and SAC scalability experiments.

## Host ports

| Service | URL |
|---|---|
| Gateway A | http://localhost:8080 |
| SAC | http://localhost:8081 |
| Gateway B | http://localhost:8082 |
| Ledger adapter | http://localhost:8083 |

## Protocol flow

1. Gateway A generates a fresh nonce and requests authorization from the SAC.
2. The SAC evaluates policy, constructs the signed session context and capability, generates `S_SAC` and `S_auth`, and provisions the authorization material to both gateways.
3. Both gateways verify the SAC authorization package and cached ledger epoch.
4. Gateway A performs ML-KEM-768 encapsulation and derives the candidate session key.
5. Gateway A signs the handshake initiation (`SigA`), binding the session identifier, gateway identities, device pseudonym, ML-KEM ciphertext, nonce, SAC capability signature, and expiry.
6. Gateway B verifies `SigA`, performs ML-KEM-768 decapsulation, and derives the same candidate session key.
7. Gateway B generates direction-bound `TagB`, signs the response as `SigB`, and returns both to Gateway A.
8. Gateway A verifies `SigB` and then verifies `TagB`.
9. Gateway A generates direction-bound `TagA` and sends it to Gateway B.
10. Gateway B verifies `TagA`.
11. The session becomes usable only after Gateway B accepts `TagA` and Gateway A receives the successful confirmation response.
12. Gateway A submits the session commitment asynchronously after session establishment.

## Timing definitions

### SAC-inclusive E2E latency

`e2e_ns` starts immediately before Gateway A sends the SAC authorization request and ends only after Gateway B has verified `TagA` and Gateway A has received the successful reciprocal-confirmation response.

It includes SAC interaction, Docker-network transport, authorization verification, ML-KEM-768 operations, HKDF-SHA-256 key derivation, Ed25519 gateway signature generation and verification, direction-bound HMAC-SHA-256 key confirmation, serialization, scheduling, and gateway processing.

It excludes ledger enqueue, ledger finality, periodic revocation lookup, and later data-plane traffic.



### Gateway cryptographic processing

Gateway cryptographic processing includes authorization verification where applicable, ML-KEM operations, HKDF-SHA-256, Ed25519 handshake signing and verification, and direction-bound HMAC-SHA-256 confirmation operations.

`gateway_a_total_crypto_ns` includes Gateway A authorization verification, ML-KEM encapsulation, KDF, `SigA` generation, `SigB` verification, `TagB` verification, and `TagA` generation.

`gateway_b_total_crypto_ns` includes `SigA` verification, ML-KEM decapsulation, KDF, `TagB` generation, `SigB` generation, and final `TagA` verification.

These values are cumulative cryptographic-processing measurements and are not wall-clock E2E intervals.

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

The performance measurements reported by the previous implementation are being regenerated after alignment of the executable protocol with the formal model. The revised protocol adds reciprocal key confirmation (`TagA`/`TagB`) and authenticated gateway handshake messages (`SigA`/`SigB`), so earlier latency measurements are not directly comparable to the current implementation.

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

## Reproduction commands

Build and start:

    docker compose up -d --build
    docker compose ps

Run tests:

    docker compose run --rm loadgen pytest -q /app/tests

Run E2E trials:

    ./scripts/run_e2e_repeated.sh
    python3 scripts/aggregate_repeated.py e2e
    python3 scripts/aggregate_breakdown.py

Run SAC trials:

    ./scripts/run_sac_repeated.sh
    python3 scripts/aggregate_repeated.py sac

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

## Manuscript alignment

A requirement to confirm or retrieve a new per-session ledger commitment before key derivation would put the ledger on the critical path and contradict the off-path claim.

`R_IOTA` is public freshness context, not secret entropy. Session secrecy must rely on the ML-KEM shared secret and confidential SAC inputs.
