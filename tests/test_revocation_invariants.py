import base64
import os
import sys
from pathlib import Path

import pytest
from fastapi import HTTPException

# The ledger adapter requires a valid 32-byte epoch digest at import time.
os.environ.setdefault(
    "LEDGER_EPOCH_DIGEST_B64",
    base64.b64encode(b"e" * 32).decode(),
)
os.environ.setdefault("LEDGER_MODE", "simulated")

sys.path.insert(
    0,
    str(
        Path(__file__).resolve().parents[1]
        / "services/ledger-adapter"
    ),
)

from app import main as adapter
from shared.splittrust.models import (
    LedgerCommitStatus,
    LedgerRevocationRequest,
)


def clear_adapter_state():
    adapter.records.clear()
    adapter.started_ns.clear()
    adapter.commitment_jobs_by_session.clear()

    adapter.revocation_records.clear()
    adapter.revocation_started_ns.clear()
    adapter.revocation_jobs_by_session.clear()

    while not adapter.queue.empty():
        adapter.queue.get_nowait()
        adapter.queue.task_done()

    while not adapter.revocation_queue.empty():
        adapter.revocation_queue.get_nowait()
        adapter.revocation_queue.task_done()


@pytest.fixture(autouse=True)
def reset_adapter_state():
    clear_adapter_state()
    yield
    clear_adapter_state()

def install_session_commitment(
    session_id: str,
    *,
    status: str,
    ledger_identifier: str | None = None,
) -> str:
    job_id = f"commit-{session_id}"

    adapter.records[job_id] = LedgerCommitStatus(
        job_id=job_id,
        session_id=session_id,
        status=status,
        queued_wall_clock_ns=1,
        ledger_identifier=ledger_identifier,
    )

    adapter.commitment_jobs_by_session[session_id] = job_id
    return job_id


def make_revocation_request(
    session_id: str,
    session_anchor: str,
) -> LedgerRevocationRequest:
    return LedgerRevocationRequest(
        trace_id="revocation-test",
        session_id=session_id,
        session_anchor=session_anchor,
        revocation_commitment_b64=base64.b64encode(
            b"r" * 32
        ).decode(),
        requested_wall_clock_ns=1,
    )


@pytest.mark.asyncio
async def test_revocation_rejected_before_session_commitment_confirmation():
    session_id = "01" * 16

    install_session_commitment(
        session_id,
        status="queued",
    )

    request = make_revocation_request(
        session_id,
        "simulated:unconfirmed-anchor",
    )

    with pytest.raises(HTTPException) as error:
        await adapter.submit_revocation(request)

    assert error.value.status_code == 409
    assert (
        error.value.detail
        == "Session commitment is not yet confirmed"
    )

    assert session_id not in adapter.revocation_jobs_by_session
    assert not adapter.revocation_records


@pytest.mark.asyncio
async def test_revocation_rejected_when_session_anchor_does_not_match():
    session_id = "02" * 16
    correct_anchor = "simulated:correct-anchor"

    install_session_commitment(
        session_id,
        status="confirmed",
        ledger_identifier=correct_anchor,
    )

    request = make_revocation_request(
        session_id,
        "simulated:wrong-anchor",
    )

    with pytest.raises(HTTPException) as error:
        await adapter.submit_revocation(request)

    assert error.value.status_code == 409
    assert (
        error.value.detail
        == "Revocation session anchor does not match confirmed commitment"
    )

    assert session_id not in adapter.revocation_jobs_by_session
    assert not adapter.revocation_records


@pytest.mark.asyncio
async def test_correctly_anchored_revocation_is_accepted_and_discoverable():
    session_id = "03" * 16
    correct_anchor = "simulated:confirmed-session-anchor"

    install_session_commitment(
        session_id,
        status="confirmed",
        ledger_identifier=correct_anchor,
    )

    request = make_revocation_request(
        session_id,
        correct_anchor,
    )

    accepted = await adapter.submit_revocation(request)

    assert accepted.session_id == session_id
    assert accepted.status == "queued"

    job_id = accepted.job_id

    assert adapter.revocation_jobs_by_session[session_id] == job_id

    queued_record = adapter.revocation_records[job_id]

    assert queued_record.session_id == session_id
    assert queued_record.session_anchor == correct_anchor
    assert queued_record.status == "queued"

    # Simulate completion by the ledger worker.  This test is about
    # the anchor invariant and lookup path, not simulated finality.
    queued_record.status = "confirmed"
    queued_record.confirmed_wall_clock_ns = 2
    queued_record.ledger_final_ns = 1

    resolved = await adapter.session_revocation_status(session_id)

    assert resolved.job_id == job_id
    assert resolved.session_id == session_id
    assert resolved.status == "confirmed"
    assert resolved.session_anchor == correct_anchor
