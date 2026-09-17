from typing import Literal

from pydantic import BaseModel, Field


class AuthorizationRequest(BaseModel):
    trace_id: str
    gateway_a_did: str
    gateway_b_did: str
    device_handle: str
    action: str
    requested_ttl_seconds: int = Field(default=60, ge=1, le=3600)
    nonce_a_b64: str


class SessionContext(BaseModel):
    session_id: str
    gateway_a_did: str
    gateway_b_did: str
    device_pseudonym: str
    issued_at_ns: int
    expires_at_ns: int
    ledger_epoch_digest_b64: str
    r_iota_b64: str
    salt_commitment_b64: str


class CapabilityClaims(BaseModel):
    session_id: str
    gateway_a_did: str
    gateway_b_did: str
    device_pseudonym: str
    action: str
    expires_at_ns: int


class SignedSessionPackage(BaseModel):
    context: SessionContext
    capability: CapabilityClaims
    context_signature_b64: str
    capability_signature_b64: str


class EncryptedAuthorization(BaseModel):
    trace_id: str
    signed_package: SignedSessionPackage
    secret_nonce_b64: str
    encrypted_secrets_b64: str


class GatewayBProvisionRequest(BaseModel):
    authorization: EncryptedAuthorization


class GatewayBProvisionResponse(BaseModel):
    session_id: str
    accepted: bool
    gateway_b_verification_ns: int


class AuthorizationResponse(BaseModel):
    authorization: EncryptedAuthorization
    sac_policy_ns: int
    sac_context_ns: int
    sac_signing_ns: int
    sac_gateway_b_roundtrip_ns: int
    sac_total_processing_ns: int
    gateway_b_verification_ns: int


class KemPublicKeyResponse(BaseModel):
    algorithm: str
    public_key_b64: str


class HandshakeRequest(BaseModel):
    trace_id: str
    session_id: str
    kem_ciphertext_b64: str
    nonce_a_b64: str


class HandshakeResponse(BaseModel):
    session_id: str
    nonce_b_b64: str
    confirmation_tag_b64: str
    gateway_b_decapsulation_ns: int
    gateway_b_kdf_ns: int
    gateway_b_mac_ns: int
    gateway_b_total_crypto_ns: int


class LedgerCommitRequest(BaseModel):
    trace_id: str
    session_id: str
    commitment_b64: str
    session_usable_wall_clock_ns: int


class LedgerCommitAccepted(BaseModel):
    job_id: str
    session_id: str
    status: Literal["queued"]


class LedgerCommitStatus(BaseModel):
    job_id: str
    session_id: str
    status: Literal[
        "queued", "submitting", "confirming", "confirmed", "failed"
    ]
    queued_wall_clock_ns: int
    confirmed_wall_clock_ns: int | None = None
    ledger_final_ns: int | None = None
    submit_latency_ns: int | None = None
    confirmation_latency_ns: int | None = None
    ledger_identifier: str | None = None
    lookup_status: str | None = None
    failure_kind: str | None = None
    error: str | None = None


class SessionRequest(BaseModel):
    device_handle: str = "actuator-r"
    action: str = "operate"
    requested_ttl_seconds: int = Field(default=60, ge=1, le=3600)


class SessionMetrics(BaseModel):
    trace_id: str
    session_id: str
    usable: bool
    ledger_mode: str
    e2e_ns: int
    authorization_path_ns: int
    sac_total_processing_ns: int
    sac_policy_ns: int
    sac_context_ns: int
    sac_signing_ns: int
    sac_gateway_b_roundtrip_ns: int
    gateway_a_authorization_verification_ns: int
    gateway_a_encapsulation_ns: int
    gateway_a_kdf_ns: int
    gateway_a_confirmation_verification_ns: int
    gateway_a_total_crypto_ns: int
    gateway_b_verification_ns: int
    gateway_b_decapsulation_ns: int
    gateway_b_kdf_ns: int
    gateway_b_mac_ns: int
    gateway_b_total_crypto_ns: int
    gateway_b_handshake_roundtrip_ns: int
    ledger_enqueue_ns: int
    ledger_job_id: str | None = None
