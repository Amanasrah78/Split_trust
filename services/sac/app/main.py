import asyncio
import os
import uuid
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException

from shared.splittrust.crypto import (
    derive_device_pseudonym,
    derive_ledger_freshness,
    derive_salt_commitment,
    ed25519_private_key_from_seed,
    ed25519_public_key_bytes,
    encrypt_authorization,
    random_bytes,
    sign_object,
)
from shared.splittrust.encoding import b64decode, b64encode
from shared.splittrust.models import (
    AuthorizationRequest,
    AuthorizationResponse,
    CapabilityClaims,
    GatewayBProvisionRequest,
    GatewayBProvisionResponse,
    SessionContext,
    SignedSessionPackage,
)
from shared.splittrust.observability import (
    log_event,
    monotonic_ns,
    wall_clock_ns,
)

SERVICE = "sac"
GATEWAY_A_DID = os.getenv(
    "GATEWAY_A_DID",
    "did:iota:gateway-a",
)

GATEWAY_B_DID = os.getenv(
    "GATEWAY_B_DID",
    "did:iota:gateway-b",
)

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

GATEWAY_B_URL = os.getenv(
    "GATEWAY_B_URL",
    "http://gateway-b:8000",
)

LEDGER_URL = os.getenv(
    "LEDGER_URL",
    "http://ledger-adapter:8000",
)

ALLOWED_ACTIONS = {
    item.strip()
    for item in os.getenv(
        "ALLOWED_ACTIONS",
        "operate,read,status",
    ).split(",")
    if item.strip()
}

DOMAIN_PAIR_POLICIES = {
    (source_did, destination_did): ALLOWED_ACTIONS
    for source_did in REGISTERED_GATEWAY_DIDS
    for destination_did in REGISTERED_GATEWAY_DIDS
    if source_did != destination_did
}


SIGNING_SEED = b64decode(os.environ["SAC_SIGNING_SEED_B64"])
CHANNEL_KEY_A = b64decode(os.environ["SAC_CHANNEL_KEY_A_B64"])
CHANNEL_KEY_B = b64decode(os.environ["SAC_CHANNEL_KEY_B_B64"])
DEVICE_ROOT = b64decode(os.environ["DEVICE_ROOT_B64"])

if len(CHANNEL_KEY_A) != 32 or len(CHANNEL_KEY_B) != 32:
    raise RuntimeError("Each SAC channel key must decode to 32 bytes")
if len(DEVICE_ROOT) != 32:
    raise RuntimeError("DEVICE_ROOT_B64 must decode to 32 bytes")

SIGNING_KEY = ed25519_private_key_from_seed(SIGNING_SEED)
PUBLIC_KEY_BYTES = ed25519_public_key_bytes(SIGNING_KEY)


async def fetch_ledger_epoch(client: httpx.AsyncClient) -> bytes:
    last_error: Exception | None = None

    for _ in range(60):
        try:
            response = await client.get(f"{LEDGER_URL}/epoch")
            response.raise_for_status()
            digest = b64decode(response.json()["epoch_digest_b64"])
            if len(digest) != 32:
                raise ValueError("Ledger epoch digest must contain 32 bytes")
            return digest
        except Exception as exc:
            last_error = exc
            await asyncio.sleep(0.25)

    raise RuntimeError(
        f"Unable to load the ledger epoch: {last_error}"
    )


@asynccontextmanager
async def lifespan(app: FastAPI):
    client = httpx.AsyncClient(timeout=10.0)
    app.state.client = client
    app.state.ledger_epoch_digest = await fetch_ledger_epoch(client)

    log_event(
        SERVICE,
        "startup_complete",
        "startup",
        ledger_epoch_cached=True,
    )

    yield
    await client.aclose()


app = FastAPI(
    title="Split-Trust Session Authorization Controller",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": SERVICE,
        "ledger_epoch_cached": hasattr(
            app.state,
            "ledger_epoch_digest",
        ),
    }


@app.get("/public-key")
async def public_key() -> dict[str, str]:
    return {
        "algorithm": "Ed25519",
        "public_key_b64": b64encode(PUBLIC_KEY_BYTES),
    }


@app.post(
    "/authorize",
    response_model=AuthorizationResponse,
)
async def authorize(
    request: AuthorizationRequest,
) -> AuthorizationResponse:
    total_started = monotonic_ns()

    policy_started = monotonic_ns()

    pair_policy = DOMAIN_PAIR_POLICIES.get(
        (
            request.gateway_a_did,
            request.gateway_b_did,
        )
    )

    if pair_policy is None:
        raise HTTPException(
            status_code=403,
            detail="Cross-domain gateway pair is not authorized",
        )

    if request.action not in pair_policy:
        raise HTTPException(
            status_code=403,
            detail="Action is not allowed for this domain pair",
        )
    if not request.device_handle.strip():
        raise HTTPException(status_code=403, detail="Invalid device handle")

    nonce_a = b64decode(request.nonce_a_b64)
    if len(nonce_a) != 32:
        raise HTTPException(
            status_code=400,
            detail="Gateway nonce must contain 32 bytes",
        )

    policy_ns = monotonic_ns() - policy_started
    context_started = monotonic_ns()

    session_id = uuid.uuid4().hex
    issued_at_ns = wall_clock_ns()
    expires_at_ns = (
        issued_at_ns + request.requested_ttl_seconds * 1_000_000_000
    )

    s_sac = random_bytes(32)
    s_auth = random_bytes(32)
    device_salt = random_bytes(32)
    ledger_digest = app.state.ledger_epoch_digest

    device_pseudonym = derive_device_pseudonym(
        DEVICE_ROOT,
        session_id,
        issued_at_ns,
        device_salt,
    )
    r_iota = derive_ledger_freshness(session_id, ledger_digest)
    salt_commitment = derive_salt_commitment(session_id, s_sac)

    context = SessionContext(
        session_id=session_id,
        gateway_a_did=request.gateway_a_did,
        gateway_b_did=request.gateway_b_did,
        device_pseudonym=device_pseudonym,
        issued_at_ns=issued_at_ns,
        expires_at_ns=expires_at_ns,
        ledger_epoch_digest_b64=b64encode(ledger_digest),
        r_iota_b64=b64encode(r_iota),
        salt_commitment_b64=b64encode(salt_commitment),
    )

    capability = CapabilityClaims(
        session_id=session_id,
        gateway_a_did=request.gateway_a_did,
        gateway_b_did=request.gateway_b_did,
        device_pseudonym=device_pseudonym,
        action=request.action,
        expires_at_ns=expires_at_ns,
    )

    context_ns = monotonic_ns() - context_started
    signing_started = monotonic_ns()

    package = SignedSessionPackage(
        context=context,
        capability=capability,
        context_signature_b64=sign_object(SIGNING_KEY, context),
        capability_signature_b64=sign_object(
            SIGNING_KEY,
            capability,
        ),
    )

    authorization_a = encrypt_authorization(
        request.trace_id,
        package,
        CHANNEL_KEY_A,
        s_sac,
        s_auth,
    )
    authorization_b = encrypt_authorization(
        request.trace_id,
        package,
        CHANNEL_KEY_B,
        s_sac,
        s_auth,
    )

    signing_ns = monotonic_ns() - signing_started
    gateway_b_started = monotonic_ns()

    try:
        response = await app.state.client.post(
            f"{GATEWAY_B_URL}/authorizations",
            json=GatewayBProvisionRequest(
                authorization=authorization_b
            ).model_dump(mode="json"),
        )
        response.raise_for_status()
        gateway_b_result = GatewayBProvisionResponse.model_validate(
            response.json()
        )
    except httpx.HTTPError as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Gateway B provisioning failed: {exc}",
        ) from exc

    gateway_b_roundtrip_ns = monotonic_ns() - gateway_b_started

    if not gateway_b_result.accepted:
        raise HTTPException(
            status_code=502,
            detail="Gateway B rejected the authorization package",
        )

    total_ns = monotonic_ns() - total_started

    log_event(
        SERVICE,
        "authorization_issued",
        request.trace_id,
        session_id=session_id,
        policy_ns=policy_ns,
        context_ns=context_ns,
        signing_ns=signing_ns,
        gateway_b_roundtrip_ns=gateway_b_roundtrip_ns,
        total_processing_ns=total_ns,
    )

    return AuthorizationResponse(
        authorization=authorization_a,
        sac_policy_ns=policy_ns,
        sac_context_ns=context_ns,
        sac_signing_ns=signing_ns,
        sac_gateway_b_roundtrip_ns=gateway_b_roundtrip_ns,
        sac_total_processing_ns=total_ns,
        gateway_b_verification_ns=(
            gateway_b_result.gateway_b_verification_ns
        ),
    )
