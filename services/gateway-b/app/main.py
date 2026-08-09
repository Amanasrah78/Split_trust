import asyncio
import hmac as stdlib_hmac
import os
from contextlib import asynccontextmanager
from dataclasses import dataclass

import httpx
from fastapi import FastAPI, HTTPException

from shared.splittrust.crypto import (
    KEM_ALGORITHM,
    confirmation_tag,
    decrypt_authorization,
    derive_ledger_freshness,
    derive_salt_commitment,
    derive_session_key,
    generate_kem_keypair,
    kem_decapsulate,
    random_bytes,
    verify_signed_package,
)
from shared.splittrust.encoding import b64decode, b64encode
from shared.splittrust.models import (
    GatewayBProvisionRequest,
    GatewayBProvisionResponse,
    HandshakeRequest,
    HandshakeResponse,
    KemPublicKeyResponse,
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
SAC_URL = os.getenv("SAC_URL", "http://sac:8000")
LEDGER_URL = os.getenv("LEDGER_URL", "http://ledger-adapter:8000")
CHANNEL_KEY = b64decode(os.environ["SAC_CHANNEL_KEY_B_B64"])

if len(CHANNEL_KEY) != 32:
    raise RuntimeError("Gateway B channel key must decode to 32 bytes")


@dataclass
class StoredAuthorization:
    package: SignedSessionPackage
    s_sac: bytes
    s_auth: bytes
    verification_ns: int
    used: bool = False


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

    kem_public_key, kem_secret_key = generate_kem_keypair()

    app.state.client = client
    app.state.sac_public_key = sac_public_key
    app.state.ledger_epoch = ledger_epoch
    app.state.kem_public_key = kem_public_key
    app.state.kem_secret_key = kem_secret_key
    app.state.authorizations = {}

    log_event(
        SERVICE,
        "startup_complete",
        "startup",
        kem_algorithm=KEM_ALGORITHM,
        ledger_epoch_cached=True,
    )

    yield
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

        if context.gateway_a_did != GATEWAY_A_DID:
            raise ValueError("Gateway A DID mismatch")
        if context.gateway_b_did != GATEWAY_B_DID:
            raise ValueError("Gateway B DID mismatch")
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
        tag = confirmation_tag(
            session_key,
            context.session_id,
            nonce_a,
            nonce_b,
            ciphertext,
            stored.s_auth,
        )
        mac_ns = monotonic_ns() - mac_started
    except Exception:
        stored.used = False
        raise

    total_crypto_ns = decapsulation_ns + kdf_ns + mac_ns

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
        nonce_b_b64=b64encode(nonce_b),
        confirmation_tag_b64=b64encode(tag),
        gateway_b_decapsulation_ns=decapsulation_ns,
        gateway_b_kdf_ns=kdf_ns,
        gateway_b_mac_ns=mac_ns,
        gateway_b_total_crypto_ns=total_crypto_ns,
    )
