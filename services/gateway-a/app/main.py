import asyncio
import hmac as stdlib_hmac
import os
from dataclasses import dataclass
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException

from shared.splittrust.crypto import (
    CONFIRMATION_DIR_A,
    CONFIRMATION_DIR_B,
    KEM_ALGORITHM,
    confirmation_tag,
    decrypt_authorization,
    derive_ledger_freshness,
    derive_salt_commitment,
    derive_session_commitment,
    derive_revocation_commitment,
    derive_session_key,
    kem_encapsulate,
    random_bytes,
    verify_confirmation_tag,
    verify_signed_package,
    ed25519_private_key_from_seed,
    gateway_a_handshake_signature_payload,
    gateway_b_handshake_signature_payload,
    sign_object,
    verify_object,
)
from shared.splittrust.encoding import b64decode, b64encode
from shared.splittrust.models import (
    AuthorizationRequest,
    AuthorizationResponse,
    HandshakeConfirmationRequest,
    HandshakeConfirmationResponse,
    HandshakeRequest,
    HandshakeResponse,
    LedgerCommitAccepted,
    LedgerCommitRequest,
    LedgerRevocationAccepted,
    LedgerRevocationRequest,
    SessionMetrics,
    SessionRequest,
)
from shared.splittrust.observability import (
    log_event,
    monotonic_ns,
    new_trace_id,
    wall_clock_ns,
)

SERVICE = "gateway-a"
GATEWAY_A_DID = os.getenv("GATEWAY_A_DID", "did:iota:gateway-a")
GATEWAY_B_DID = os.getenv("GATEWAY_B_DID", "did:iota:gateway-b")
SAC_URL = os.getenv("SAC_URL", "http://sac:8000")
GATEWAY_B_URL = os.getenv("GATEWAY_B_URL", "http://gateway-b:8000")
LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger-adapter:8000")
CHANNEL_KEY = b64decode(os.environ["SAC_CHANNEL_KEY_A_B64"])
GATEWAY_A_SIGNING_SEED = b64decode(
    os.environ["GATEWAY_A_SIGNING_SEED_B64"]
)

GATEWAY_B_SIGNING_PUBLIC_KEY = b64decode(
    os.environ["GATEWAY_B_SIGNING_PUBLIC_KEY_B64"]
)

if len(GATEWAY_A_SIGNING_SEED) != 32:
    raise RuntimeError(
        "Gateway A signing seed must decode to 32 bytes"
    )

if len(GATEWAY_B_SIGNING_PUBLIC_KEY) != 32:
    raise RuntimeError(
        "Gateway B signing public key must decode to 32 bytes"
    )

if len(CHANNEL_KEY) != 32:
    raise RuntimeError("Gateway A channel key must decode to 32 bytes")


async def fetch_json(
    client: httpx.AsyncClient,
    url: str,
) -> dict:
    last_error: Exception | None = None

    for _ in range(60):
        try:
            response = await client.get(url)
            response.raise_for_status()
            return response.json()
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(0.25)

    raise RuntimeError(f"Unable to load {url}: {last_error}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = httpx.AsyncClient(timeout=30.0)

    sac_data, ledger_data, gateway_b_data = await asyncio.gather(
        fetch_json(client, f"{SAC_URL}/public-key"),
        fetch_json(client, f"{LEDGER_URL}/epoch"),
        fetch_json(client, f"{GATEWAY_B_URL}/kem-public-key"),
    )

    sac_public_key = b64decode(sac_data["public_key_b64"])
    ledger_epoch = b64decode(ledger_data["epoch_digest_b64"])
    gateway_b_public_key = b64decode(
        gateway_b_data["public_key_b64"]
    )

    gateway_a_signing_key = ed25519_private_key_from_seed(
        GATEWAY_A_SIGNING_SEED
    )
    app.state.gateway_a_signing_key = gateway_a_signing_key
    app.state.gateway_b_signing_public_key = (
        GATEWAY_B_SIGNING_PUBLIC_KEY
    )
    if len(sac_public_key) != 32:
        raise RuntimeError("Invalid SAC public key length")
    if len(ledger_epoch) != 32:
        raise RuntimeError("Invalid ledger epoch length")
    if gateway_b_data["algorithm"] != KEM_ALGORITHM:
        raise RuntimeError("Gateway B uses an unexpected KEM")

    app.state.client = client
    app.state.sac_public_key = sac_public_key
    app.state.ledger_epoch = ledger_epoch
    app.state.ledger_mode = ledger_data["ledger_mode"]
    app.state.gateway_b_public_key = gateway_b_public_key
    app.state.established_sessions = {}

    log_event(
        SERVICE,
        "startup_complete",
        "startup",
        kem_algorithm=KEM_ALGORITHM,
        ledger_epoch_cached=True,
    )

    yield
    await client.aclose()

@dataclass
class EstablishedSessionRecord:
    trace_id: str
    session_id: str
    session_commitment: bytes
    established_wall_clock_ns: int
    revocation_job_id: str | None = None
    revocation_requested_wall_clock_ns: int | None = None

app = FastAPI(
    title="Split-Trust Gateway A",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": SERVICE,
        "kem_algorithm": KEM_ALGORITHM,
        "ledger_mode": app.state.ledger_mode,
        "ledger_epoch_cached": True,
    }

@app.post("/sessions/{session_id}/revoke")
async def revoke_session(
    session_id: str,
    reason: str = "manual",
) -> dict[str, object]:
    session: EstablishedSessionRecord | None = (
        app.state.established_sessions.get(session_id)
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown or non-established session",
        )

    if session.revocation_job_id is not None:
        return {
            "session_id": session.session_id,
            "job_id": session.revocation_job_id,
            "requested_wall_clock_ns": (
                session.revocation_requested_wall_clock_ns
            ),
            "already_requested": True,
        }

    requested_at = wall_clock_ns()

    revocation_commitment = derive_revocation_commitment(
        session_id=session.session_id,
        session_commitment=session.session_commitment,
        revocation_context=reason,
        revoked_at_ns=requested_at,
    )

    try:
        response = await app.state.client.post(
            f"{LEDGER_URL}/revocations",
            json=LedgerRevocationRequest(
                trace_id=session.trace_id,
                session_id=session.session_id,
                revocation_commitment_b64=b64encode(
                    revocation_commitment
                ),
                requested_wall_clock_ns=requested_at,
            ).model_dump(mode="json"),
        )

        response.raise_for_status()

        result = LedgerRevocationAccepted.model_validate(
            response.json()
        )

    except Exception as exc:
        log_event(
            SERVICE,
            "revocation_enqueue_failed",
            session.trace_id,
            session_id=session.session_id,
            error=str(exc),
        )

        raise HTTPException(
            status_code=502,
            detail="Unable to submit revocation to ledger",
        ) from exc

    session.revocation_job_id = result.job_id
    session.revocation_requested_wall_clock_ns = requested_at

    log_event(
        SERVICE,
        "revocation_requested",
        session.trace_id,
        session_id=session.session_id,
        revocation_job_id=result.job_id,
        requested_wall_clock_ns=requested_at,
        reason=reason,
    )

    return {
        "session_id": session.session_id,
        "job_id": result.job_id,
        "status": result.status,
        "requested_wall_clock_ns": requested_at,
        "already_requested": False,
    }
@app.post(
    "/sessions",
    response_model=SessionMetrics,
)
async def establish_session(
    request: SessionRequest,
) -> SessionMetrics:
    trace_id = new_trace_id()
    nonce_a = random_bytes(32)

    authorization_request = AuthorizationRequest(
        trace_id=trace_id,
        gateway_a_did=GATEWAY_A_DID,
        gateway_b_did=GATEWAY_B_DID,
        device_handle=request.device_handle,
        action=request.action,
        requested_ttl_seconds=request.requested_ttl_seconds,
        nonce_a_b64=b64encode(nonce_a),
    )

    # t0: Gateway A sends the authorization request.
    e2e_started = monotonic_ns()

    try:
        sac_response = await app.state.client.post(
            f"{SAC_URL}/authorize",
            json=authorization_request.model_dump(mode="json"),
        )
        # t3: Authorization material has reached Gateway A.
        authorization_received = monotonic_ns()
        sac_response.raise_for_status()
        authorization_result = AuthorizationResponse.model_validate(
            sac_response.json()
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"SAC authorization failed: {exc}",
        ) from exc

    authorization_path_ns = authorization_received - e2e_started
    authorization_verification_started = monotonic_ns()

    authorization = authorization_result.authorization
    package = authorization.signed_package
    context = package.context

    try:
        s_sac, s_auth = decrypt_authorization(
            authorization,
            CHANNEL_KEY,
        )
        verify_signed_package(
            app.state.sac_public_key,
            package,
        )

        if context.gateway_a_did != GATEWAY_A_DID:
            raise ValueError("Gateway A DID mismatch")
        if context.gateway_b_did != GATEWAY_B_DID:
            raise ValueError("Gateway B DID mismatch")
        if context.expires_at_ns <= wall_clock_ns():
            raise ValueError("Authorization has expired")
        if package.capability.action != request.action:
            raise ValueError("Authorized action mismatch")

        received_epoch = b64decode(
            context.ledger_epoch_digest_b64
        )
        if not stdlib_hmac.compare_digest(
            received_epoch,
            app.state.ledger_epoch,
        ):
            raise ValueError("Ledger epoch mismatch")

        expected_freshness = derive_ledger_freshness(
            context.session_id,
            app.state.ledger_epoch,
        )
        if not stdlib_hmac.compare_digest(
            expected_freshness,
            b64decode(context.r_iota_b64),
        ):
            raise ValueError("Ledger freshness mismatch")

        expected_salt_commitment = derive_salt_commitment(
            context.session_id,
            s_sac,
        )
        if not stdlib_hmac.compare_digest(
            expected_salt_commitment,
            b64decode(context.salt_commitment_b64),
        ):
            raise ValueError("SAC salt commitment mismatch")
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail=f"Authorization verification failed: {exc}",
        ) from exc

    authorization_verification_ns = (
        monotonic_ns() - authorization_verification_started
    )

    encapsulation_started = monotonic_ns()
    kem_ciphertext, kem_shared_secret = kem_encapsulate(
        app.state.gateway_b_public_key
    )
    encapsulation_ns = monotonic_ns() - encapsulation_started

    kdf_started = monotonic_ns()
    session_key = derive_session_key(
        kem_shared_secret,
        s_sac,
        s_auth,
        b64decode(context.r_iota_b64),
        context.session_id,
        context.gateway_a_did,
        context.gateway_b_did,
        context.device_pseudonym,
    )
    kdf_ns = monotonic_ns() - kdf_started
    kem_ciphertext_b64 = b64encode(kem_ciphertext)
    nonce_a_b64 = b64encode(nonce_a)

    gateway_a_signature_payload = (
        gateway_a_handshake_signature_payload(
            session_id=context.session_id,
            device_pseudonym=context.device_pseudonym,
            gateway_a_did=context.gateway_a_did,
            gateway_b_did=context.gateway_b_did,
            kem_ciphertext_b64=kem_ciphertext_b64,
            nonce_a_b64=nonce_a_b64,
            capability_signature_b64=(
                package.capability_signature_b64
            ),
            expires_at_ns=context.expires_at_ns,
        )
    )

    gateway_a_signature_generation_started = monotonic_ns()

    gateway_a_signature_b64 = sign_object(
        app.state.gateway_a_signing_key,
        gateway_a_signature_payload,
    )

    gateway_a_signature_generation_ns = (
        monotonic_ns() - gateway_a_signature_generation_started
    )

    handshake_request = HandshakeRequest(
        trace_id=trace_id,
        session_id=context.session_id,
        kem_ciphertext_b64=kem_ciphertext_b64,
        nonce_a_b64=nonce_a_b64,
        gateway_a_signature_b64=gateway_a_signature_b64,
    )


    handshake_started = monotonic_ns()

    try:
        handshake_response = await app.state.client.post(
            f"{GATEWAY_B_URL}/handshake",
            json=handshake_request.model_dump(mode="json"),
        )
        handshake_response.raise_for_status()
        handshake_result = HandshakeResponse.model_validate(
            handshake_response.json()
        )


    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Gateway B handshake failed: {exc}",
        ) from exc

    handshake_roundtrip_ns = monotonic_ns() - handshake_started

    if handshake_result.session_id != context.session_id:
        raise HTTPException(
            status_code=400,
            detail="Gateway B returned the wrong session identifier",
        )



    gateway_b_signature_payload = (
        gateway_b_handshake_signature_payload(
            session_id=context.session_id,
            device_pseudonym=context.device_pseudonym,
            gateway_a_did=context.gateway_a_did,
            gateway_b_did=context.gateway_b_did,
            nonce_b_b64=handshake_result.nonce_b_b64,
            kem_ciphertext_b64=kem_ciphertext_b64,
            capability_signature_b64=(
                package.capability_signature_b64
            ),
            expires_at_ns=context.expires_at_ns,
            confirmation_tag_b64=(
                handshake_result.confirmation_tag_b64
            ),
        )
    )
       # Verify Gateway B signature before accepting its key confirmation.
    gateway_b_signature_verification_started = monotonic_ns()

    try:
        verify_object(
            app.state.gateway_b_signing_public_key,
            gateway_b_signature_payload,
            handshake_result.gateway_b_signature_b64,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Gateway B handshake signature verification failed",
        ) from exc

    gateway_b_signature_verification_ns = (
        monotonic_ns() - gateway_b_signature_verification_started
    )

    # Decode Gateway B's nonce only after its signed response is verified.
    nonce_b = b64decode(handshake_result.nonce_b_b64)

    if len(nonce_b) != 32:
        raise HTTPException(
            status_code=400,
            detail="Gateway B nonce must contain 32 bytes",
        )

    # Verify TagB from Gateway B.
    confirmation_verification_started = monotonic_ns()

    try:
        verify_confirmation_tag(
            session_key,
            context.session_id,
            nonce_a,
            nonce_b,
            kem_ciphertext,
            s_auth,
            CONFIRMATION_DIR_B,
            b64decode(handshake_result.confirmation_tag_b64),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Gateway B key confirmation failed",
        ) from exc

    confirmation_verification_ns = (
        monotonic_ns() - confirmation_verification_started
    )
    # 2. Create TagA
    confirmation_tag_a_started = monotonic_ns()

    tag_a = confirmation_tag(
        session_key,
        context.session_id,
        nonce_a,
        nonce_b,
        kem_ciphertext,
        s_auth,
        CONFIRMATION_DIR_A,
    )

    confirmation_tag_a_ns = (
        monotonic_ns() - confirmation_tag_a_started
    )

    # 3. Send TagA back to GB
    confirmation_started = monotonic_ns()

    try:
        confirmation_response = await app.state.client.post(
            f"{GATEWAY_B_URL}/handshake-confirm",
            json=HandshakeConfirmationRequest(
                trace_id=trace_id,
                session_id=context.session_id,
                confirmation_tag_a_b64=b64encode(tag_a),
            ).model_dump(mode="json"),
        )

        confirmation_response.raise_for_status()

        confirmation_result = (
            HandshakeConfirmationResponse.model_validate(
                confirmation_response.json()
            )
        )

    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Gateway B confirmation failed: {exc}",
        ) from exc

    confirmation_roundtrip_ns = (
        monotonic_ns() - confirmation_started
    )

    # 4. Make sure GB really accepted TagA
    if (
        confirmation_result.session_id != context.session_id
        or not confirmation_result.established
    ):
        raise HTTPException(
            status_code=400,
            detail="Gateway B did not confirm session establishment",
        )

    # 5. Only now is the session fully established
    session_usable_wall_clock_ns = wall_clock_ns()
    e2e_ns = monotonic_ns() - e2e_started

    gateway_a_total_crypto_ns = (
        authorization_verification_ns
        + encapsulation_ns
        + kdf_ns
        + gateway_a_signature_generation_ns
        + gateway_b_signature_verification_ns
        + confirmation_verification_ns
        + confirmation_tag_a_ns
    )


    commitment = derive_session_commitment(
        context.session_id,
        context.gateway_a_did,
        context.gateway_b_did,
        context.device_pseudonym,
        session_key,
    )

    app.state.established_sessions[context.session_id] = (
        EstablishedSessionRecord(
            trace_id=trace_id,
            session_id=context.session_id,
            session_commitment=commitment,
            established_wall_clock_ns=session_usable_wall_clock_ns,
        )
    )


    # This starts only after t5 and cannot affect e2e_ns.
    ledger_enqueue_started = monotonic_ns()
    ledger_job_id: str | None = None

    try:
        ledger_response = await app.state.client.post(
            f"{LEDGER_URL}/commitments",
            json=LedgerCommitRequest(
                trace_id=trace_id,
                session_id=context.session_id,
                commitment_b64=b64encode(commitment),
                session_usable_wall_clock_ns=(
                    session_usable_wall_clock_ns
                ),
            ).model_dump(mode="json"),
        )
        ledger_response.raise_for_status()
        ledger_result = LedgerCommitAccepted.model_validate(
            ledger_response.json()
        )
        ledger_job_id = ledger_result.job_id
    except Exception as exc:
        log_event(
            SERVICE,
            "ledger_enqueue_failed",
            trace_id,
            session_id=context.session_id,
            error=str(exc),
        )

    ledger_enqueue_ns = monotonic_ns() - ledger_enqueue_started

    log_event(
        SERVICE,
        "session_usable",
        trace_id,
        session_id=context.session_id,
        e2e_ns=e2e_ns,
        authorization_path_ns=authorization_path_ns,
        gateway_a_total_crypto_ns=gateway_a_total_crypto_ns,
        ledger_enqueue_ns=ledger_enqueue_ns,
        ledger_started_after_session_usable=True,
    )

    return SessionMetrics(
        trace_id=trace_id,
        session_id=context.session_id,
        usable=True,
        ledger_mode=app.state.ledger_mode,
        e2e_ns=e2e_ns,
        authorization_path_ns=authorization_path_ns,
        sac_total_processing_ns=(
            authorization_result.sac_total_processing_ns
        ),
        sac_policy_ns=authorization_result.sac_policy_ns,
        sac_context_ns=authorization_result.sac_context_ns,
        sac_signing_ns=authorization_result.sac_signing_ns,
        sac_gateway_b_roundtrip_ns=(
            authorization_result.sac_gateway_b_roundtrip_ns
        ),
        gateway_a_authorization_verification_ns=(
            authorization_verification_ns
        ),
        gateway_a_encapsulation_ns=encapsulation_ns,
        gateway_a_kdf_ns=kdf_ns,
        gateway_a_confirmation_verification_ns=(
            confirmation_verification_ns
        ),
        gateway_a_total_crypto_ns=gateway_a_total_crypto_ns,
        gateway_b_verification_ns=(
            authorization_result.gateway_b_verification_ns
        ),
        gateway_a_signature_generation_ns=(
            gateway_a_signature_generation_ns
        ),
        gateway_a_gateway_b_signature_verification_ns=(
            gateway_b_signature_verification_ns
        ),
        gateway_b_decapsulation_ns=(
            handshake_result.gateway_b_decapsulation_ns
        ),
        gateway_b_kdf_ns=handshake_result.gateway_b_kdf_ns,
        gateway_b_mac_ns=handshake_result.gateway_b_mac_ns,
        gateway_b_total_crypto_ns=(
            handshake_result.gateway_b_total_crypto_ns
            + confirmation_result.gateway_b_confirmation_verification_ns
        ),
        gateway_b_gateway_a_signature_verification_ns=(
            handshake_result.gateway_b_gateway_a_signature_verification_ns
        ),
        gateway_b_signature_generation_ns=(
            handshake_result.gateway_b_signature_generation_ns
        ),
        gateway_b_handshake_roundtrip_ns=handshake_roundtrip_ns,
        ledger_enqueue_ns=ledger_enqueue_ns,
        ledger_job_id=ledger_job_id,
        gateway_a_confirmation_tag_ns=confirmation_tag_a_ns,
        gateway_b_confirmation_verification_ns=(
            confirmation_result.gateway_b_confirmation_verification_ns
        ),
        gateway_confirmation_roundtrip_ns=confirmation_roundtrip_ns,
    )
