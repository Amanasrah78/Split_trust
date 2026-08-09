# SplitTrust_IOTA_STAP_PQKEM

## Overview

This repository contains the formal Tamarin model and supporting material for the research work:

**“Split-Trust Authorization and Post-Quantum Session Establishment for Cross-Domain IIoT Systems”**

The model captures a **cross-domain Industrial IoT authentication and authorization protocol** that combines:

- Post-quantum key establishment (RLWE-based KEM abstraction)
- Split-trust session key derivation
- SAC-mediated authorization
- Ledger-backed integrity and freshness using IOTA

The protocol is formally verified using the **Tamarin Prover** under the symbolic Dolev–Yao model.

---

## Author

**Ahmed Manasrah**  
Yarmouk University, Jordan  

---

## Key Contributions

The modeled protocol provides:

- **Split-trust security** across three independent domains:
  - Gateway domain (GA, GB)
  - Authorization domain (SAC)
  - Ledger domain (IOTA)

- **Post-quantum secure key establishment** using RLWE-KEM abstraction

- **Authorization-bound session establishment** via:
  - SAC-issued session context
  - Capability tokens
  - Confidential authorization secret \( S_{\text{auth}} \)

- **Ledger-backed guarantees**:
  - Freshness
  - Auditability
  - Revocation ordering

- **Formal verification** of:
  - Authentication
  - Key secrecy
  - Replay resistance
  - UKS resistance
  - KCI resilience

---

## Model Description

The Tamarin model implements the protocol in phases:

### Phase 0 — Identity Anchoring
- DID creation and anchoring
- Verifiable credential issuance

### Phase 1 — Registration
- Device registration linked to DID
- Ledger commitment of registration state

### Phase 2 — Authorization and Session Setup
- SAC issues:
  - Session identifier
  - Salt contribution \( S_{\mathrm{SAC}} \)
  - Authorization token
  - Confidential secret \( S_{\text{auth}} \)

- Gateway-to-gateway session establishment:
  - Abstract KEM exchange (`CT`, `Z`)
  - Session key derivation using `kdf`

### Phase 3 — Commitment and Revocation
- Session anchoring on IOTA
- Revocation enforcement via ledger

---

## Symbolic Modeling Abstractions

| Protocol Concept            | Tamarin Symbol |
|----------------------------|---------------|
| RLWE ciphertext            | `CT`          |
| Shared secret \(K_{LTW}\)  | `Z`           |
| Authorization secret       | `AuthS`       |
| Session key                | `kdf(...)`    |

The RLWE-KEM is abstracted as:
- `CT`: public ciphertext
- `Z`: secret shared value bound via `!KEM_Map`

This captures IND-CCA security without modeling lattice algebra.

---

## Adversary Model

The model assumes a **Dolev–Yao adversary** with:

- Full control over the communication network:
  - interception
  - modification
  - replay
  - injection

- Ability to compromise:
  - gateway long-term keys (`Reveal_GB_Ltk`)

Assumptions:
- SAC is **not compromised** unless explicitly modeled
- Authorization secret \( S_{\text{auth}} \) remains confidential
- Ledger is **immutable and publicly readable**

---

## Verified Security Properties

All lemmas are verified under **all-traces semantics**.

### Authentication
- Mutual authentication
- Aliveness
- Injective agreement (replay resistance)

### Session Key Security
- Session key secrecy
- Key agreement
- Key independence

### Attack Resistance
- Unknown key-share (UKS) resistance
- Replay protection (implicit via injective agreement + freshness)
- Key-compromise impersonation (KCI) resilience

### Ledger Guarantees
- Session anchoring correctness
- Revocation ordering

### Split-Trust Guarantees
- Session requires SAC-issued authorization
- Compromise of a single domain is insufficient

---

## Running the Model

### Requirements
- Tamarin Prover (version 1.9.x or later)

### Execution

```bash
tamarin-prover interactive model.spthy

# Execution
- In the code, the GB signature in gb_resp is included but not explicitly verified by GA_Finish_Session_PQKEM. I reflected that in the comments rather than pretending the signature is modeled as a checked precondition.
- In SAC_Issue_AuthSecret, the fact is !AuthSecret(IDsess, didR, ~AuthS), so I described it as a trusted provision to both gateways, which matches your intended semantics even though the fact itself is global/persistent.
