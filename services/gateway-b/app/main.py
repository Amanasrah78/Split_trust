import asyncio
import hmac as stdlib_hmac
import os
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass

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
    derive_session_key,
    generate_kem_keypair,
    kem_decapsulate,
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
    GatewayBProvisionRequest,
    GatewayBProvisionResponse,
    HandshakeConfirmationRequest,
    HandshakeConfirmationResponse,
    HandshakeRequest,
    HandshakeResponse,
    KemPublicKeyResponse,
    LedgerCommitStatus,
    LedgerRevocationStatus,
    SignedSessionPackage,
)
from shared.splittrust.observability import (
    log_event,
    monotonic_ns,
    wall_clock_ns,
)

SERVICE = "gateway-b"
GATEWAY_A_DID = os.getenv("GATEWAY_A_DID", "did:iota:gateway-a")
GATEWAY_B_DID = os.getenv("GATEWAY_B_DID", "did:iota:gateway-b")
REGISTERED_GATEWAY_DIDS = frozenset(
    item.strip()
    for item in os.getenv(
        "REGISTERED_GATEWAY_DIDS",
        f"{GATEWAY_A_DID},{GATEWAY_B_DID}",
    ).split(",")
    if item.strip()
)

if len(REGISTERED_GATEWAY_DIDS) < 2:
    raise RuntimeError(
        "REGISTERED_GATEWAY_DIDS must contain at least two gateway DIDs"
    )
SAC_URL = os.getenv("SAC_URL", "http://sac:8000")
LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger-adapter:8000")
REVOCATION_POLL_INTERVAL_MS = int(
    os.getenv("REVOCATION_POLL_INTERVAL_MS", "100")
)
CHANNEL_KEY = b64decode(os.environ["SAC_CHANNEL_KEY_B_B64"])
GATEWAY_B_SIGNING_SEED = b64decode(
    os.environ["GATEWAY_B_SIGNING_SEED_B64"]
)

GATEWAY_A_SIGNING_PUBLIC_KEY = b64decode(
    os.environ["GATEWAY_A_SIGNING_PUBLIC_KEY_B64"]
)

if len(GATEWAY_B_SIGNING_SEED) != 32:
    raise RuntimeError(
        "Gateway B signing seed must decode to 32 bytes"
    )

if len(GATEWAY_A_SIGNING_PUBLIC_KEY) != 32:
    raise RuntimeError(
        "Gateway A signing public key must decode to 32 bytes"
    )

if len(CHANNEL_KEY) != 32:
    raise RuntimeError("Gateway B channel key must decode to 32 bytes")


@dataclass
class StoredAuthorization:
    package: SignedSessionPackage
    s_sac: bytes
    s_auth: bytes
    verification_ns: int
    used: bool = False

@dataclass
class PendingHandshake:
    trace_id: str
    session_id: str
    session_key: bytes
    nonce_a: bytes
    nonce_b: bytes
    ciphertext: bytes
    s_auth: bytes

@dataclass
class EstablishedSession:
    trace_id: str
    session_id: str
    action: str
    expires_at_ns: int
    established_wall_clock_ns: int
    revoked: bool = False
    revoked_wall_clock_ns: int | None = None
    revocation_confirmed_wall_clock_ns: int | None = None
    revocation_job_id: str | None = None

async def fetch_startup_value(
    client: httpx.AsyncClient,
    url: str,
    field: str,
) -> bytes:
    last_error: Exception | None = None

    for _ in range(60):
        try:
            response = await client.get(url)
            response.raise_for_status()
            value = b64decode(response.json()[field])
            if len(value) != 32:
                raise ValueError(f"{field} must contain 32 bytes")
            return value
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(0.25)

    raise RuntimeError(f"Unable to load {field}: {last_error}")

async def revocation_monitor(app: FastAPI) -> None:
    while True:
        sessions = list(app.state.established_sessions.values())

        for session in sessions:
            if session.revoked:
                continue

            if session.expires_at_ns <= wall_clock_ns():
                continue

            try:
                response = await app.state.client.get(
                    f"{LEDGER_URL}/session-revocations/"
                    f"{session.session_id}"
                )

                if response.status_code == 404:
                    continue

                response.raise_for_status()
                revocation = LedgerRevocationStatus.model_validate(
                    response.json()
                )

                if revocation.status != "confirmed":
                    continue

                anchor_response = await app.state.client.get(
                    f"{LEDGER_URL}/session-commitments/"
                    f"{session.session_id}"
                )

                if anchor_response.status_code == 404:
                    continue

                anchor_response.raise_for_status()

                commitment = LedgerCommitStatus.model_validate(
                    anchor_response.json()
                )

                if commitment.status != "confirmed":
                    continue

                if not commitment.ledger_identifier:
                    continue

                if revocation.session_anchor != commitment.ledger_identifier:
                    log_event(
                        SERVICE,
                        "revocation_anchor_mismatch",
                        session.trace_id,
                        session_id=session.session_id,
                        revocation_job_id=revocation.job_id,
                        revocation_session_anchor=revocation.session_anchor,
                        confirmed_session_anchor=commitment.ledger_identifier,
                    )
                    continue

                detected_at = wall_clock_ns()
                confirmed_at = revocation.confirmed_wall_clock_ns

                session.revoked = True
                session.revoked_wall_clock_ns = detected_at
                session.revocation_confirmed_wall_clock_ns = confirmed_at
                session.revocation_job_id = revocation.job_id

                detection_latency_ns = None
                if isinstance(confirmed_at, int):
                    detection_latency_ns = detected_at - confirmed_at

                log_event(
                    SERVICE,
                    "ledger_revocation_enforced",
                    session.trace_id,
                    session_id=session.session_id,
                    revocation_job_id=session.revocation_job_id,
                    session_anchor=revocation.session_anchor,
                    confirmed_wall_clock_ns=confirmed_at,
                    enforced_wall_clock_ns=detected_at,
                    detection_latency_ns=detection_latency_ns,
                )

            except httpx.HTTPError:
                continue

        await asyncio.sleep(
            REVOCATION_POLL_INTERVAL_MS / 1000
        )

@asynccontextmanager
async def lifespan(app: FastAPI):
    client = httpx.AsyncClient(timeout=10.0)

    sac_public_key, ledger_epoch = await asyncio.gather(
        fetch_startup_value(
            client,
            f"{SAC_URL}/public-key",
            "public_key_b64",
        ),
        fetch_startup_value(
            client,
            f"{LEDGER_URL}/epoch",
            "epoch_digest_b64",
        ),
    )

    gateway_b_signing_key = ed25519_private_key_from_seed(
        GATEWAY_B_SIGNING_SEED
    )
    app.state.gateway_b_signing_key = gateway_b_signing_key
    app.state.gateway_a_signing_public_key = (
        GATEWAY_A_SIGNING_PUBLIC_KEY
    )
    kem_public_key, kem_secret_key = generate_kem_keypair()

    app.state.client = client
    app.state.sac_public_key = sac_public_key
    app.state.ledger_epoch = ledger_epoch
    app.state.kem_public_key = kem_public_key
    app.state.kem_secret_key = kem_secret_key
    app.state.authorizations = {}
    app.state.pending_handshakes = {}
    app.state.established_sessions = {}
    revocation_monitor_task = asyncio.create_task(
        revocation_monitor(app)
    )

    log_event(
        SERVICE,
        "startup_complete",
        "startup",
        kem_algorithm=KEM_ALGORITHM,
        ledger_epoch_cached=True,
    )

    yield

    revocation_monitor_task.cancel()
    with suppress(asyncio.CancelledError):
        await revocation_monitor_task

    await client.aclose()


app = FastAPI(
    title="Split-Trust Gateway B",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": SERVICE,
        "kem_algorithm": KEM_ALGORITHM,
        "pending_authorizations": len(app.state.authorizations),
    }


@app.post("/sessions/{session_id}/validate-action")
async def validate_session_action(
    session_id: str,
    action: str,
) -> dict[str, object]:
    session: EstablishedSession | None = (
        app.state.established_sessions.get(session_id)
    )

    if session is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown or non-established session",
        )

    if session.revoked:
        raise HTTPException(
            status_code=403,
            detail="Session has been revoked",
        )

    if session.expires_at_ns <= wall_clock_ns():
        raise HTTPException(
            status_code=403,
            detail="Session has expired",
        )

    if not stdlib_hmac.compare_digest(action, session.action):
        raise HTTPException(
            status_code=403,
            detail="Action is not authorized for this session",
        )

    return {
        "session_id": session.session_id,
        "action": action,
        "authorized": True,
        "revoked": False,
    }

@app.get(
    "/kem-public-key",
    response_model=KemPublicKeyResponse,
)
async def kem_public_key() -> KemPublicKeyResponse:
    return KemPublicKeyResponse(
        algorithm=KEM_ALGORITHM,
        public_key_b64=b64encode(app.state.kem_public_key),
    )


@app.post(
    "/authorizations",
    response_model=GatewayBProvisionResponse,
)
async def provision_authorization(
    request: GatewayBProvisionRequest,
) -> GatewayBProvisionResponse:
    started = monotonic_ns()
    authorization = request.authorization
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

        if context.gateway_a_did not in REGISTERED_GATEWAY_DIDS:
            raise ValueError("Unknown Gateway A DID")
        if context.gateway_b_did not in REGISTERED_GATEWAY_DIDS:
            raise ValueError("Unknown Gateway B DID")
        if context.gateway_a_did == context.gateway_b_did:
            raise ValueError(
                "Source and destination gateways must be different"
            )
        if context.expires_at_ns <= wall_clock_ns():
            raise ValueError("Authorization has expired")

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

        expected_commitment = derive_salt_commitment(
            context.session_id,
            s_sac,
        )
        if not stdlib_hmac.compare_digest(
            expected_commitment,
            b64decode(context.salt_commitment_b64),
        ):
            raise ValueError("SAC salt commitment mismatch")
    except Exception as exc:
        log_event(
            SERVICE,
            "authorization_verification_failed",
            authorization.trace_id,
            error=f"{type(exc).__name__}: {exc}",
        )
        raise HTTPException(
            status_code=400,
            detail=f"Authorization verification failed: {exc}",
        ) from exc

    verification_ns = monotonic_ns() - started

    app.state.authorizations[context.session_id] = StoredAuthorization(
        package=package,
        s_sac=s_sac,
        s_auth=s_auth,
        verification_ns=verification_ns,
    )

    log_event(
        SERVICE,
        "authorization_stored",
        authorization.trace_id,
        session_id=context.session_id,
        verification_ns=verification_ns,
    )

    return GatewayBProvisionResponse(
        session_id=context.session_id,
        accepted=True,
        gateway_b_verification_ns=verification_ns,
    )


@app.post(
    "/handshake",
    response_model=HandshakeResponse,
)
async def handshake(
    request: HandshakeRequest,
) -> HandshakeResponse:
    stored: StoredAuthorization | None = (
        app.state.authorizations.get(request.session_id)
    )

    if stored is None:
        raise HTTPException(
            status_code=404,
            detail="No authorization exists for this session",
        )
    if stored.used:
        raise HTTPException(
            status_code=409,
            detail="Authorization has already been consumed",
        )

    context = stored.package.context
    if context.expires_at_ns <= wall_clock_ns():
        raise HTTPException(
            status_code=403,
            detail="Authorization has expired",
        )

    gateway_a_signature_payload = (
        gateway_a_handshake_signature_payload(
            session_id=context.session_id,
            device_pseudonym=context.device_pseudonym,
            gateway_a_did=context.gateway_a_did,
            gateway_b_did=context.gateway_b_did,
            kem_ciphertext_b64=request.kem_ciphertext_b64,
            nonce_a_b64=request.nonce_a_b64,
            capability_signature_b64=(
                stored.package.capability_signature_b64
            ),
            expires_at_ns=context.expires_at_ns,
        )
    )

    gateway_a_signature_verification_started = monotonic_ns()

    try:
        verify_object(
            app.state.gateway_a_signing_public_key,
            gateway_a_signature_payload,
            request.gateway_a_signature_b64,
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Gateway A handshake signature verification failed",
        ) from exc

    gateway_a_signature_verification_ns = (
        monotonic_ns() - gateway_a_signature_verification_started
    )
    ciphertext = b64decode(request.kem_ciphertext_b64)
    nonce_a = b64decode(request.nonce_a_b64)
    if len(nonce_a) != 32:
        raise HTTPException(
            status_code=400,
            detail="Gateway A nonce must contain 32 bytes",
        )

    stored.used = True

    try:
        decapsulation_started = monotonic_ns()
        kem_shared_secret = kem_decapsulate(
            app.state.kem_secret_key,
            ciphertext,
        )
        decapsulation_ns = monotonic_ns() - decapsulation_started

        kdf_started = monotonic_ns()
        session_key = derive_session_key(
            kem_shared_secret,
            stored.s_sac,
            stored.s_auth,
            b64decode(context.r_iota_b64),
            context.session_id,
            context.gateway_a_did,
            context.gateway_b_did,
            context.device_pseudonym,
        )
        kdf_ns = monotonic_ns() - kdf_started

        nonce_b = random_bytes(32)
        mac_started = monotonic_ns()
        tag_b = confirmation_tag(
            session_key,
            context.session_id,
            nonce_a,
            nonce_b,
            ciphertext,
            stored.s_auth,
            CONFIRMATION_DIR_B,
        )

        mac_ns = monotonic_ns() - mac_started
    except Exception:
        stored.used = False
        raise
    nonce_b_b64 = b64encode(nonce_b)
    tag_b_b64 = b64encode(tag_b)

    gateway_b_signature_payload = (
        gateway_b_handshake_signature_payload(
            session_id=context.session_id,
            device_pseudonym=context.device_pseudonym,
            gateway_a_did=context.gateway_a_did,
            gateway_b_did=context.gateway_b_did,
            nonce_b_b64=nonce_b_b64,
            kem_ciphertext_b64=request.kem_ciphertext_b64,
            capability_signature_b64=(
                stored.package.capability_signature_b64
            ),
            expires_at_ns=context.expires_at_ns,
            confirmation_tag_b64=tag_b_b64,
        )
    )

    gateway_b_signature_generation_started = monotonic_ns()

    gateway_b_signature_b64 = sign_object(
        app.state.gateway_b_signing_key,
        gateway_b_signature_payload,
    )

    gateway_b_signature_generation_ns = (
        monotonic_ns() - gateway_b_signature_generation_started
    )
    total_crypto_ns = (
        gateway_a_signature_verification_ns
        + decapsulation_ns
        + kdf_ns
        + mac_ns
        + gateway_b_signature_generation_ns
    )
    app.state.pending_handshakes[context.session_id] = PendingHandshake(
    trace_id=request.trace_id,
    session_id=context.session_id,
    session_key=session_key,
    nonce_a=nonce_a,
    nonce_b=nonce_b,
    ciphertext=ciphertext,
    s_auth=stored.s_auth,
)

    log_event(
        SERVICE,
        "key_confirmation_created",
        request.trace_id,
        session_id=context.session_id,
        decapsulation_ns=decapsulation_ns,
        kdf_ns=kdf_ns,
        mac_ns=mac_ns,
        total_crypto_ns=total_crypto_ns,
    )


    return HandshakeResponse(
        session_id=context.session_id,
        nonce_b_b64=nonce_b_b64,
        confirmation_tag_b64=tag_b_b64,
        gateway_b_signature_b64=gateway_b_signature_b64,
        gateway_b_gateway_a_signature_verification_ns=(
            gateway_a_signature_verification_ns
        ),
        gateway_b_decapsulation_ns=decapsulation_ns,
        gateway_b_kdf_ns=kdf_ns,
        gateway_b_mac_ns=mac_ns,
        gateway_b_signature_generation_ns=(
            gateway_b_signature_generation_ns
        ),
        gateway_b_total_crypto_ns=total_crypto_ns,
    )
@app.post(
    "/handshake-confirm",
    response_model=HandshakeConfirmationResponse,
)
async def confirm_handshake(
    request: HandshakeConfirmationRequest,
) -> HandshakeConfirmationResponse:
    pending: PendingHandshake | None = (
        app.state.pending_handshakes.get(request.session_id)
    )

    if pending is None:
        raise HTTPException(
            status_code=404,
            detail="No pending handshake exists for this session",
        )

    verification_started = monotonic_ns()

    try:
        verify_confirmation_tag(
            pending.session_key,
            pending.session_id,
            pending.nonce_a,
            pending.nonce_b,
            pending.ciphertext,
            pending.s_auth,
            CONFIRMATION_DIR_A,
            b64decode(request.confirmation_tag_a_b64),
        )
    except Exception as exc:
        raise HTTPException(
            status_code=400,
            detail="Gateway A key confirmation failed",
        ) from exc

    verification_ns = monotonic_ns() - verification_started

    stored: StoredAuthorization | None = (
        app.state.authorizations.get(request.session_id)
    )

    if stored is None:
        raise HTTPException(
            status_code=404,
            detail="Authorization state is unavailable for this session",
        )

    app.state.established_sessions[request.session_id] = EstablishedSession(
        trace_id=request.trace_id,
        session_id=request.session_id,
        action=stored.package.capability.action,
        expires_at_ns=stored.package.context.expires_at_ns,
        established_wall_clock_ns=wall_clock_ns(),
    )

    del app.state.pending_handshakes[request.session_id]

    log_event(
            SERVICE,
            "session_established",
            request.trace_id,
            session_id=request.session_id,
            confirmation_verification_ns=verification_ns,
        )

    return HandshakeConfirmationResponse(
        session_id=request.session_id,
        established=True,
        gateway_b_confirmation_verification_ns=verification_ns,
    )