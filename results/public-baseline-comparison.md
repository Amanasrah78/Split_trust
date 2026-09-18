# Public reproducible baseline

The repository [GU-Cryptography/quantum-safe-mqtt](https://github.com/GU-Cryptography/quantum-safe-mqtt)
provides a public proof-of-concept MQTT authentication handshake. Its KEM
variant uses Kyber-512 and its signature variant uses Dilithium; it does not
implement cross-domain authorization, a SAC, or ledger anchoring. The upstream
paper describes the implementation as a handshake-only prototype and reports
that the client and broker were run separately.

The checked-in upstream CSV files contain the following descriptive values
(100 KEM observations and 20 signature observations):

| Upstream variant | Observations | Mean connection time (ms) | p95 (ms) |
|---|---:|---:|---:|
| Kyber-512 KEM | 100 | 23.564 | 46.929 |
| Dilithium signature | 20 | 42.393 | 47.999 |

These values are not a controlled comparison with this testbed. The upstream
measurements use different hardware, software, message flows, sample counts,
and cryptographic parameters than the present ML-KEM-768 split-trust system.
They are therefore useful only as a reproducible standalone PQ-handshake
reference. A controlled comparison would require running the upstream client
and broker under the same host, container limits, warm-up policy, trial count,
and measurement boundary used by this project.

The related IIoT implementation [fratrung/did-iiot-dht](https://github.com/fratrung/did-iiot-dht)
is also publicly available and combines DIDs, verifiable credentials,
Dilithium, Kyber, and a DHT-based verifiable data registry. It is a useful
qualitative architecture reference, but it does not provide a directly
comparable end-to-end benchmark for the present SAC-plus-ledger protocol.
