import os

import oqs
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from shared.splittrust.encoding import (
    b64decode,
    b64encode,
    canonical_json,
    sha256,
)
from shared.splittrust.models import (
    EncryptedAuthorization,
    SignedSessionPackage,
)

KEM_ALGORITHM = "ML-KEM-768"
DOMAIN_ROOT = b"SAC-SPLIT-TRUST/v1"
SESSION_KEY_INFO = b"session-key/v1"
CONFIRMATION_INFO = b"key-confirmation/v1"
CONFIRMATION_DIR_A = b"dirA"
CONFIRMATION_DIR_B = b"dirB"

def random_bytes(length: int = 32) -> bytes:
    return os.urandom(length)


def frame(*parts: bytes) -> bytes:
    return b"".join(
        len(part).to_bytes(4, byteorder="big") + part
        for part in parts
    )


def generate_kem_keypair() -> tuple[bytes, bytes]:
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        public_key = kem.generate_keypair()
        secret_key = kem.export_secret_key()
    return public_key, secret_key


def kem_encapsulate(public_key: bytes) -> tuple[bytes, bytes]:
    with oqs.KeyEncapsulation(KEM_ALGORITHM) as kem:
        ciphertext, shared_secret = kem.encap_secret(public_key)
    return ciphertext, shared_secret


def kem_decapsulate(
    secret_key: bytes,
    ciphertext: bytes,
) -> bytes:
    with oqs.KeyEncapsulation(KEM_ALGORITHM, secret_key) as kem:
        return kem.decap_secret(ciphertext)


def ed25519_private_key_from_seed(seed: bytes) -> Ed25519PrivateKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must contain exactly 32 bytes")
    return Ed25519PrivateKey.from_private_bytes(seed)


def ed25519_public_key_bytes(
    private_key: Ed25519PrivateKey,
) -> bytes:
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )


def sign_object(
    private_key: Ed25519PrivateKey,
    value: object,
) -> str:
    return b64encode(private_key.sign(canonical_json(value)))


def verify_object(
    public_key_bytes: bytes,
    value: object,
    signature_b64: str,
) -> None:
    public_key = Ed25519PublicKey.from_public_bytes(public_key_bytes)
    public_key.verify(
        b64decode(signature_b64),
        canonical_json(value),
    )

def gateway_a_handshake_signature_payload(
    session_id: str,
    device_pseudonym: str,
    gateway_a_did: str,
    gateway_b_did: str,
    kem_ciphertext_b64: str,
    nonce_a_b64: str,
    capability_signature_b64: str,
    expires_at_ns: int,
) -> dict[str, object]:
    return {
        "message_type": "ga_kem",
        "session_id": session_id,
        "device_pseudonym": device_pseudonym,
        "gateway_a_did": gateway_a_did,
        "gateway_b_did": gateway_b_did,
        "kem_ciphertext_b64": kem_ciphertext_b64,
        "nonce_a_b64": nonce_a_b64,
        "capability_signature_b64": capability_signature_b64,
        "expires_at_ns": expires_at_ns,
    }


def gateway_b_handshake_signature_payload(
    session_id: str,
    device_pseudonym: str,
    gateway_a_did: str,
    gateway_b_did: str,
    nonce_b_b64: str,
    kem_ciphertext_b64: str,
    capability_signature_b64: str,
    expires_at_ns: int,
    confirmation_tag_b64: str,
) -> dict[str, object]:
    return {
        "message_type": "gb_resp",
        "session_id": session_id,
        "device_pseudonym": device_pseudonym,
        "gateway_a_did": gateway_a_did,
        "gateway_b_did": gateway_b_did,
        "nonce_b_b64": nonce_b_b64,
        "kem_ciphertext_b64": kem_ciphertext_b64,
        "capability_signature_b64": capability_signature_b64,
        "expires_at_ns": expires_at_ns,
        "confirmation_tag_b64": confirmation_tag_b64,
    }
def verify_signed_package(
    public_key_bytes: bytes,
    package: SignedSessionPackage,
) -> None:
    verify_object(
        public_key_bytes,
        package.context,
        package.context_signature_b64,
    )
    verify_object(
        public_key_bytes,
        package.capability,
        package.capability_signature_b64,
    )

    context = package.context
    capability = package.capability

    if capability.session_id != context.session_id:
        raise InvalidSignature("Session identifier mismatch")
    if capability.gateway_a_did != context.gateway_a_did:
        raise InvalidSignature("Gateway A binding mismatch")
    if capability.gateway_b_did != context.gateway_b_did:
        raise InvalidSignature("Gateway B binding mismatch")
    if capability.device_pseudonym != context.device_pseudonym:
        raise InvalidSignature("Device binding mismatch")
    if capability.expires_at_ns != context.expires_at_ns:
        raise InvalidSignature("Expiry binding mismatch")


def encrypt_authorization(
    trace_id: str,
    package: SignedSessionPackage,
    channel_key: bytes,
    s_sac: bytes,
    s_auth: bytes,
) -> EncryptedAuthorization:
    if len(channel_key) != 32:
        raise ValueError("AES-256-GCM channel key must contain 32 bytes")
    if len(s_sac) != 32 or len(s_auth) != 32:
        raise ValueError("SAC inputs must each contain 32 bytes")

    nonce = random_bytes(12)
    plaintext = s_sac + s_auth
    ciphertext = AESGCM(channel_key).encrypt(
        nonce,
        plaintext,
        canonical_json(package),
    )

    return EncryptedAuthorization(
        trace_id=trace_id,
        signed_package=package,
        secret_nonce_b64=b64encode(nonce),
        encrypted_secrets_b64=b64encode(ciphertext),
    )


def decrypt_authorization(
    authorization: EncryptedAuthorization,
    channel_key: bytes,
) -> tuple[bytes, bytes]:
    plaintext = AESGCM(channel_key).decrypt(
        b64decode(authorization.secret_nonce_b64),
        b64decode(authorization.encrypted_secrets_b64),
        canonical_json(authorization.signed_package),
    )

    if len(plaintext) != 64:
        raise ValueError("Invalid authorization-secret payload length")

    return plaintext[:32], plaintext[32:]


def derive_device_pseudonym(
    device_root: bytes,
    session_id: str,
    issued_at_ns: int,
    device_salt: bytes,
) -> str:
    return b64encode(
        sha256(
            frame(
                device_root,
                session_id.encode(),
                str(issued_at_ns).encode(),
                device_salt,
            )
        )
    )


def derive_ledger_freshness(
    session_id: str,
    ledger_epoch_digest: bytes,
) -> bytes:
    return sha256(
        frame(
            session_id.encode(),
            ledger_epoch_digest,
        )
    )


def derive_salt_commitment(
    session_id: str,
    s_sac: bytes,
) -> bytes:
    return sha256(frame(session_id.encode(), s_sac))


def derive_session_key(
    kem_shared_secret: bytes,
    s_sac: bytes,
    s_auth: bytes,
    r_iota: bytes,
    session_id: str,
    gateway_a_did: str,
    gateway_b_did: str,
    device_pseudonym: str,
) -> bytes:
    ikm = frame(
        DOMAIN_ROOT,
        kem_shared_secret,
        s_sac,
        s_auth,
        r_iota,
        session_id.encode(),
        gateway_a_did.encode(),
        gateway_b_did.encode(),
        device_pseudonym.encode(),
    )

    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=SESSION_KEY_INFO,
    ).derive(ikm)


def confirmation_tag(
    session_key: bytes,
    session_id: str,
    nonce_a: bytes,
    nonce_b: bytes,
    kem_ciphertext: bytes,
    s_auth: bytes,
    direction: bytes,
) -> bytes:
    if direction not in {
        CONFIRMATION_DIR_A,
        CONFIRMATION_DIR_B,
    }:
        raise ValueError("Invalid confirmation direction")

    mac = hmac.HMAC(session_key, hashes.SHA256())
    mac.update(
        frame(
            CONFIRMATION_INFO,
            session_id.encode(),
            nonce_a,
            nonce_b,
            kem_ciphertext,
            s_auth,
            direction,
        )
    )
    return mac.finalize()


def verify_confirmation_tag(
    session_key: bytes,
    session_id: str,
    nonce_a: bytes,
    nonce_b: bytes,
    kem_ciphertext: bytes,
    s_auth: bytes,
    direction: bytes,
    received_tag: bytes,
) -> None:
    if direction not in {
        CONFIRMATION_DIR_A,
        CONFIRMATION_DIR_B,
    }:
        raise ValueError("Invalid confirmation direction")

    mac = hmac.HMAC(session_key, hashes.SHA256())
    mac.update(
        frame(
            CONFIRMATION_INFO,
            session_id.encode(),
            nonce_a,
            nonce_b,
            kem_ciphertext,
            s_auth,
            direction,
        )
    )
    mac.verify(received_tag)

def derive_session_commitment(
    session_id: str,
    gateway_a_did: str,
    gateway_b_did: str,
    device_pseudonym: str,
    session_key: bytes,
) -> bytes:
    return sha256(
        frame(
            session_id.encode(),
            gateway_a_did.encode(),
            gateway_b_did.encode(),
            device_pseudonym.encode(),
            sha256(session_key),
        )
    )

def derive_revocation_commitment(
    session_id: str,
    session_commitment: bytes,
    session_anchor: str,
    device_pseudonym: str,
    revocation_context: str,
    revoked_at_ns: int,
) -> bytes:
    if len(session_commitment) != 32:
        raise ValueError("Session commitment must contain 32 bytes")

    if not session_anchor:
        raise ValueError("Session anchor must not be empty")

    if not device_pseudonym:
        raise ValueError("Device pseudonym must not be empty")

    return sha256(
        frame(
            b"splittrust-revocation-v1",
            session_id.encode(),
            session_commitment,
            session_anchor.encode(),
            device_pseudonym.encode(),
            revocation_context.encode(),
            str(revoked_at_ns).encode(),
        )
    )