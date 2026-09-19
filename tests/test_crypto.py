import os
import time

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shared.splittrust.crypto import (
    CONFIRMATION_DIR_A,
    CONFIRMATION_DIR_B,
    confirmation_tag,
    decrypt_authorization,
    derive_ledger_freshness,
    derive_salt_commitment,
    derive_session_commitment,
    derive_session_key,
    ed25519_private_key_from_seed,
    ed25519_public_key_bytes,
    encrypt_authorization,
    generate_kem_keypair,
    kem_decapsulate,
    kem_encapsulate,
    sign_object,
    verify_confirmation_tag,
    verify_signed_package,
    gateway_a_handshake_signature_payload,
    gateway_b_handshake_signature_payload,
    verify_object,
)
from shared.splittrust.encoding import b64encode
from shared.splittrust.models import (
    CapabilityClaims,
    SessionContext,
    SignedSessionPackage,
)


def make_package():
    signing_key = ed25519_private_key_from_seed(os.urandom(32))
    public_key = ed25519_public_key_bytes(signing_key)
    session_id = "0123456789abcdef0123456789abcdef"
    ledger_epoch = os.urandom(32)
    s_sac = os.urandom(32)
    issued_at = time.time_ns()

    context = SessionContext(
        session_id=session_id,
        gateway_a_did="did:iota:gateway-a",
        gateway_b_did="did:iota:gateway-b",
        device_pseudonym=b64encode(os.urandom(32)),
        issued_at_ns=issued_at,
        expires_at_ns=issued_at + 60_000_000_000,
        ledger_epoch_digest_b64=b64encode(ledger_epoch),
        r_iota_b64=b64encode(
            derive_ledger_freshness(session_id, ledger_epoch)
        ),
        salt_commitment_b64=b64encode(
            derive_salt_commitment(session_id, s_sac)
        ),
    )

    capability = CapabilityClaims(
        session_id=session_id,
        gateway_a_did=context.gateway_a_did,
        gateway_b_did=context.gateway_b_did,
        device_pseudonym=context.device_pseudonym,
        action="operate",
        expires_at_ns=context.expires_at_ns,
    )

    package = SignedSessionPackage(
        context=context,
        capability=capability,
        context_signature_b64=sign_object(signing_key, context),
        capability_signature_b64=sign_object(
            signing_key,
            capability,
        ),
    )

    return package, public_key, s_sac


def test_ml_kem_round_trip():
    public_key, secret_key = generate_kem_keypair()
    ciphertext, sender_secret = kem_encapsulate(public_key)
    receiver_secret = kem_decapsulate(secret_key, ciphertext)

    assert sender_secret == receiver_secret
    assert len(sender_secret) == 32


def test_signed_package_and_encrypted_secrets():
    package, public_key, s_sac = make_package()
    s_auth = os.urandom(32)
    channel_key = AESGCM.generate_key(bit_length=256)

    authorization = encrypt_authorization(
        "trace-id",
        package,
        channel_key,
        s_sac,
        s_auth,
    )

    recovered_s_sac, recovered_s_auth = decrypt_authorization(
        authorization,
        channel_key,
    )
    verify_signed_package(public_key, package)

    assert recovered_s_sac == s_sac
    assert recovered_s_auth == s_auth


def test_tampered_capability_is_rejected():
    package, public_key, _ = make_package()
    tampered_capability = package.capability.model_copy(
        update={"action": "read"}
    )
    tampered_package = package.model_copy(
        update={"capability": tampered_capability}
    )

    with pytest.raises(InvalidSignature):
        verify_signed_package(public_key, tampered_package)


def test_wrong_provisioning_key_is_rejected():
    package, _, s_sac = make_package()
    authorization = encrypt_authorization(
        "trace-id",
        package,
        AESGCM.generate_key(bit_length=256),
        s_sac,
        os.urandom(32),
    )

    with pytest.raises(Exception):
        decrypt_authorization(
            authorization,
            AESGCM.generate_key(bit_length=256),
        )


def test_session_derivation_and_confirmation():
    package, _, s_sac = make_package()
    context = package.context
    s_auth = os.urandom(32)
    r_iota = derive_ledger_freshness(
        context.session_id,
        os.urandom(32),
    )

    public_key, secret_key = generate_kem_keypair()
    ciphertext, sender_kem_secret = kem_encapsulate(public_key)
    receiver_kem_secret = kem_decapsulate(
        secret_key,
        ciphertext,
    )

    sender_key = derive_session_key(
        sender_kem_secret,
        s_sac,
        s_auth,
        r_iota,
        context.session_id,
        context.gateway_a_did,
        context.gateway_b_did,
        context.device_pseudonym,
    )
    receiver_key = derive_session_key(
        receiver_kem_secret,
        s_sac,
        s_auth,
        r_iota,
        context.session_id,
        context.gateway_a_did,
        context.gateway_b_did,
        context.device_pseudonym,
    )

    nonce_a = os.urandom(32)
    nonce_b = os.urandom(32)


    tag_b = confirmation_tag(
        receiver_key,
        context.session_id,
        nonce_a,
        nonce_b,
        ciphertext,
        s_auth,
        CONFIRMATION_DIR_B,
    )

    verify_confirmation_tag(
        sender_key,
        context.session_id,
        nonce_a,
        nonce_b,
        ciphertext,
        s_auth,
        CONFIRMATION_DIR_B,
        tag_b,
    )

    tag_a = confirmation_tag(
        sender_key,
        context.session_id,
        nonce_a,
        nonce_b,
        ciphertext,
        s_auth,
        CONFIRMATION_DIR_A,
    )

    verify_confirmation_tag(
        receiver_key,
        context.session_id,
        nonce_a,
        nonce_b,
        ciphertext,
        s_auth,
        CONFIRMATION_DIR_A,
        tag_a,
    )

    assert sender_key == receiver_key
    assert len(
        derive_session_commitment(
            context.session_id,
            context.gateway_a_did,
            context.gateway_b_did,
            context.device_pseudonym,
            sender_key,
        )
    ) == 32

def test_confirmation_direction_separation():
    session_key = os.urandom(32)
    session_id = "session-test"
    nonce_a = os.urandom(32)
    nonce_b = os.urandom(32)
    ciphertext = os.urandom(64)
    s_auth = os.urandom(32)

    tag_b = confirmation_tag(
        session_key,
        session_id,
        nonce_a,
        nonce_b,
        ciphertext,
        s_auth,
        CONFIRMATION_DIR_B,
    )

    with pytest.raises(Exception):
        verify_confirmation_tag(
            session_key,
            session_id,
            nonce_a,
            nonce_b,
            ciphertext,
            s_auth,
            CONFIRMATION_DIR_A,
            tag_b,
        )


def test_gateway_a_signature_rejects_tampered_handshake():
    private_key = ed25519_private_key_from_seed(os.urandom(32))
    public_key = ed25519_public_key_bytes(private_key)

    payload = gateway_a_handshake_signature_payload(
        session_id="session-1",
        device_pseudonym="device-pseudonym",
        gateway_a_did="did:iota:gateway-a",
        gateway_b_did="did:iota:gateway-b",
        kem_ciphertext_b64="ciphertext",
        nonce_a_b64="nonce-a",
        capability_signature_b64="capability-signature",
        expires_at_ns=123456789,
    )

    signature = sign_object(
        private_key,
        payload,
    )

    tampered_payload = gateway_a_handshake_signature_payload(
        session_id="session-1",
        device_pseudonym="device-pseudonym",
        gateway_a_did="did:iota:gateway-a",
        gateway_b_did="did:iota:gateway-b",
        kem_ciphertext_b64="TAMPERED-ciphertext",
        nonce_a_b64="nonce-a",
        capability_signature_b64="capability-signature",
        expires_at_ns=123456789,
    )

    with pytest.raises(Exception):
        verify_object(
            public_key,
            tampered_payload,
            signature,
        )
def test_gateway_b_signature_rejects_tampered_confirmation():
    private_key = ed25519_private_key_from_seed(os.urandom(32))
    public_key = ed25519_public_key_bytes(private_key)

    payload = gateway_b_handshake_signature_payload(
        session_id="session-1",
        device_pseudonym="device-pseudonym",
        gateway_a_did="did:iota:gateway-a",
        gateway_b_did="did:iota:gateway-b",
        nonce_b_b64="nonce-b",
        kem_ciphertext_b64="ciphertext",
        capability_signature_b64="capability-signature",
        expires_at_ns=123456789,
        confirmation_tag_b64="tag-b",
    )

    signature = sign_object(
        private_key,
        payload,
    )

    tampered_payload = gateway_b_handshake_signature_payload(
        session_id="session-1",
        device_pseudonym="device-pseudonym",
        gateway_a_did="did:iota:gateway-a",
        gateway_b_did="did:iota:gateway-b",
        nonce_b_b64="nonce-b",
        kem_ciphertext_b64="ciphertext",
        capability_signature_b64="capability-signature",
        expires_at_ns=123456789,
        confirmation_tag_b64="TAMPERED-tag-b",
    )

    with pytest.raises(Exception):
        verify_object(
            public_key,
            tampered_payload,
            signature,
        )