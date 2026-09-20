import asyncio
import os
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException, status

from .backends import IotaBackend

from shared.splittrust.encoding import b64decode
from shared.splittrust.models import (
    LedgerCommitAccepted,
    LedgerCommitRequest,
    LedgerCommitStatus,
    LedgerRevocationAccepted,
    LedgerRevocationRequest,
    LedgerRevocationStatus,
)
from shared.splittrust.observability import (
    log_event,
    monotonic_ns,
    wall_clock_ns,
)

SERVICE = "ledger-adapter"
LEDGER_MODE = os.getenv("LEDGER_MODE", "simulated")
SIMULATED_FINALITY_MS = int(
    os.getenv("LEDGER_SIMULATED_FINALITY_MS", "12000")
)
WORKER_COUNT = int(os.getenv("LEDGER_WORKER_COUNT", "64"))
LEDGER_EPOCH_DIGEST_B64 = os.environ["LEDGER_EPOCH_DIGEST_B64"]
REVOCATION_TAG_HEX = os.getenv(
    "IOTA_REVOCATION_TAG_HEX",
    "73706c69742d74727573742d72657631",
)

if LEDGER_MODE not in {"simulated", "iota"}:
    raise RuntimeError("LEDGER_MODE must be 'simulated' or 'iota'")

if len(b64decode(LEDGER_EPOCH_DIGEST_B64)) != 32:
    raise RuntimeError("LEDGER_EPOCH_DIGEST_B64 must decode to 32 bytes")

queue: asyncio.Queue[tuple[str, LedgerCommitRequest]] = asyncio.Queue()
records: dict[str, LedgerCommitStatus] = {}
started_ns: dict[str, int] = {}
commitment_jobs_by_session: dict[str, str] = {}
iota_backend: IotaBackend | None = None

revocation_queue: asyncio.Queue[
    tuple[str, LedgerRevocationRequest]
] = asyncio.Queue()

revocation_records: dict[str, LedgerRevocationStatus] = {}
revocation_started_ns: dict[str, int] = {}
revocation_jobs_by_session: dict[str, str] = {}

async def commitment_worker() -> None:
    while True:
        job_id, request = await queue.get()

        try:
            record = records[job_id]
            record.status = "submitting"

            if LEDGER_MODE == "simulated":
                await asyncio.sleep(SIMULATED_FINALITY_MS / 1000)
                record.ledger_identifier = f"simulated:{job_id}"
                record.lookup_status = "simulated"

            else:
                assert iota_backend is not None

                def submitted(identifier: str, latency_ns: int) -> None:
                    record.status = "confirming"
                    record.ledger_identifier = identifier
                    record.submit_latency_ns = latency_ns

                result = await iota_backend.submit(
                    b64decode(request.commitment_b64),
                    request.session_id,
                    on_submitted=submitted,
                )
                record.submit_latency_ns = result.submit_latency_ns
                record.confirmation_latency_ns = (
                    result.confirmation_latency_ns
                )
                record.ledger_identifier = result.identifier
                record.lookup_status = result.lookup_status

            confirmed_at = wall_clock_ns()
            record.status = "confirmed"
            record.confirmed_wall_clock_ns = confirmed_at
            record.ledger_final_ns = monotonic_ns() - started_ns[job_id]

            log_event(
                SERVICE,
                "commitment_confirmed",
                request.trace_id,
                job_id=job_id,
                session_id=request.session_id,
                ledger_final_ns=record.ledger_final_ns,
                submit_latency_ns=record.submit_latency_ns,
                confirmation_latency_ns=record.confirmation_latency_ns,
                ledger_identifier=record.ledger_identifier,
                lookup_status=record.lookup_status,
                session_usable_wall_clock_ns=(
                    request.session_usable_wall_clock_ns
                ),
            )
        except Exception as exc:
            record = records[job_id]
            record.status = "failed"
            record.ledger_final_ns = monotonic_ns() - started_ns[job_id]
            record.confirmation_latency_ns = getattr(
                exc, "confirmation_latency_ns", record.confirmation_latency_ns
            )
            record.lookup_status = getattr(
                exc, "lookup_status", record.lookup_status
            )
            record.failure_kind = type(exc).__name__
            record.error = str(exc)

            log_event(
                SERVICE,
                "commitment_failed",
                request.trace_id,
                job_id=job_id,
                session_id=request.session_id,
                ledger_final_ns=record.ledger_final_ns,
                ledger_identifier=record.ledger_identifier,
                lookup_status=record.lookup_status,
                error=str(exc),
            )
        finally:
            queue.task_done()

async def revocation_worker() -> None:
    while True:
        job_id, request = await revocation_queue.get()

        try:
            record = revocation_records[job_id]
            record.status = "submitting"

            if LEDGER_MODE == "simulated":
                await asyncio.sleep(SIMULATED_FINALITY_MS / 1000)
                record.lookup_status = "simulated"
            else:
                assert iota_backend is not None

                def submitted(identifier: str, latency_ns: int) -> None:
                    record.status = "confirming"
                    record.ledger_identifier = identifier
                    record.submit_latency_ns = latency_ns

                result = await iota_backend.submit(
                    b64decode(request.revocation_commitment_b64),
                    request.session_id,
                    on_submitted=submitted,
                    tag_hex=REVOCATION_TAG_HEX,
                )

                record.submit_latency_ns = result.submit_latency_ns
                record.confirmation_latency_ns = (
                    result.confirmation_latency_ns
                )
                record.ledger_identifier = result.identifier
                record.lookup_status = result.lookup_status

            confirmed_at = wall_clock_ns()
            record.status = "confirmed"
            record.confirmed_wall_clock_ns = confirmed_at
            record.ledger_final_ns = (
                monotonic_ns() - revocation_started_ns[job_id]
            )

            log_event(
                SERVICE,
                "revocation_confirmed",
                request.trace_id,
                job_id=job_id,
                session_id=request.session_id,
                requested_wall_clock_ns=request.requested_wall_clock_ns,
                confirmed_wall_clock_ns=confirmed_at,
                ledger_final_ns=record.ledger_final_ns,
                submit_latency_ns=record.submit_latency_ns,
                confirmation_latency_ns=record.confirmation_latency_ns,
                ledger_identifier=record.ledger_identifier,
                lookup_status=record.lookup_status,
            )

        except Exception as exc:
            record = revocation_records[job_id]
            record.status = "failed"
            record.ledger_final_ns = (
                monotonic_ns() - revocation_started_ns[job_id]
            )
            record.confirmation_latency_ns = getattr(
                exc,
                "confirmation_latency_ns",
                record.confirmation_latency_ns,
            )
            record.lookup_status = getattr(
                exc,
                "lookup_status",
                record.lookup_status,
            )
            record.failure_kind = type(exc).__name__
            record.error = str(exc)

            log_event(
                SERVICE,
                "revocation_failed",
                request.trace_id,
                job_id=job_id,
                session_id=request.session_id,
                ledger_final_ns=record.ledger_final_ns,
                ledger_identifier=record.ledger_identifier,
                lookup_status=record.lookup_status,
                error=str(exc),
            )

        finally:
            revocation_queue.task_done()

@asynccontextmanager
async def lifespan(_: FastAPI):
    global iota_backend
    if LEDGER_MODE == "iota":
        iota_backend = IotaBackend.from_environment()
    workers = [
        asyncio.create_task(commitment_worker())
        for _ in range(WORKER_COUNT)
    ] + [
        asyncio.create_task(revocation_worker())
        for _ in range(WORKER_COUNT)
    ]
    yield
    for worker in workers:
        worker.cancel()
    for worker in workers:
        with suppress(asyncio.CancelledError):
            await worker


app = FastAPI(
    title="Split-Trust Ledger Adapter",
    version="0.1.0",
    lifespan=lifespan,
)


@app.get("/health")
async def health() -> dict[str, object]:
    return {
        "status": "ok",
        "service": SERVICE,
        "ledger_mode": LEDGER_MODE,
        "queued_commitments": queue.qsize(),
        "queued_revocations": revocation_queue.qsize(),
    }


@app.get("/epoch")
async def epoch() -> dict[str, str]:
    return {
        "ledger_mode": LEDGER_MODE,
        "epoch_digest_b64": LEDGER_EPOCH_DIGEST_B64,
    }


@app.post(
    "/commitments",
    response_model=LedgerCommitAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_commitment(
    request: LedgerCommitRequest,
) -> LedgerCommitAccepted:
    commitment = b64decode(request.commitment_b64)
    if len(commitment) != 32:
        raise HTTPException(
            status_code=400,
            detail="Commitment must be a 32-byte SHA-256 digest",
        )
    existing_job_id = commitment_jobs_by_session.get(
        request.session_id
    )

    if existing_job_id is not None:
        existing_record = records.get(existing_job_id)

        if (
            existing_record is not None
            and existing_record.status != "failed"
        ):
            raise HTTPException(
                status_code=409,
                detail="A session commitment already exists for this session",
            )
    job_id = uuid.uuid4().hex
    queued_at = wall_clock_ns()

    records[job_id] = LedgerCommitStatus(
        job_id=job_id,
        session_id=request.session_id,
        status="queued",
        queued_wall_clock_ns=queued_at,
    )
    commitment_jobs_by_session[request.session_id] = job_id
    started_ns[job_id] = monotonic_ns()
    queue.put_nowait((job_id, request))

    log_event(
        SERVICE,
        "commitment_queued",
        request.trace_id,
        job_id=job_id,
        session_id=request.session_id,
        queue_depth=queue.qsize(),
    )

    return LedgerCommitAccepted(
        job_id=job_id,
        session_id=request.session_id,
        status="queued",
    )


@app.get(
    "/commitments/{job_id}",
    response_model=LedgerCommitStatus,
)
async def commitment_status(job_id: str) -> LedgerCommitStatus:
    record = records.get(job_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Unknown job identifier")
    return record

@app.get(
    "/session-commitments/{session_id}",
    response_model=LedgerCommitStatus,
)
async def session_commitment_status(
    session_id: str,
) -> LedgerCommitStatus:
    job_id = commitment_jobs_by_session.get(session_id)

    if job_id is None:
        raise HTTPException(
            status_code=404,
            detail="No commitment exists for this session",
        )

    record = records.get(job_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Session commitment record is unavailable",
        )

    return record

@app.post(
    "/revocations",
    response_model=LedgerRevocationAccepted,
    status_code=status.HTTP_202_ACCEPTED,
)
async def submit_revocation(
    request: LedgerRevocationRequest,
) -> LedgerRevocationAccepted:
    revocation_commitment = b64decode(
        request.revocation_commitment_b64
    )

    if len(revocation_commitment) != 32:
        raise HTTPException(
            status_code=400,
            detail="Revocation commitment must be a 32-byte SHA-256 digest",
        )

    commitment_job_id = commitment_jobs_by_session.get(
        request.session_id
    )

    if commitment_job_id is None:
        raise HTTPException(
            status_code=409,
            detail="Session has no ledger commitment",
        )

    commitment_record = records.get(commitment_job_id)

    if commitment_record is None:
        raise HTTPException(
            status_code=409,
            detail="Session commitment record is unavailable",
        )

    if commitment_record.status != "confirmed":
        raise HTTPException(
            status_code=409,
            detail="Session commitment is not yet confirmed",
        )

    if commitment_record.ledger_identifier is None:
        raise HTTPException(
            status_code=409,
            detail="Confirmed session commitment has no ledger anchor",
        )

    if request.session_anchor != commitment_record.ledger_identifier:
        raise HTTPException(
            status_code=409,
            detail="Revocation session anchor does not match confirmed commitment",
        )
    job_id = uuid.uuid4().hex
    queued_at = wall_clock_ns()

    revocation_records[job_id] = LedgerRevocationStatus(
        job_id=job_id,
        session_id=request.session_id,
        session_anchor=request.session_anchor,
        status="queued",
        queued_wall_clock_ns=queued_at,
    )

    revocation_started_ns[job_id] = monotonic_ns()
    revocation_jobs_by_session[request.session_id] = job_id

    revocation_queue.put_nowait((job_id, request))

    log_event(
        SERVICE,
        "revocation_queued",
        request.trace_id,
        job_id=job_id,
        session_id=request.session_id,
        requested_wall_clock_ns=request.requested_wall_clock_ns,
        queue_depth=revocation_queue.qsize(),
    )

    return LedgerRevocationAccepted(
        job_id=job_id,
        session_id=request.session_id,
        status="queued",
    )


@app.get(
    "/revocations/{job_id}",
    response_model=LedgerRevocationStatus,
)
async def revocation_status(
    job_id: str,
) -> LedgerRevocationStatus:
    record = revocation_records.get(job_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Unknown revocation job identifier",
        )

    return record

@app.get(
    "/session-revocations/{session_id}",
    response_model=LedgerRevocationStatus,
)
async def session_revocation_status(
    session_id: str,
) -> LedgerRevocationStatus:
    job_id = revocation_jobs_by_session.get(session_id)

    if job_id is None:
        raise HTTPException(
            status_code=404,
            detail="No revocation exists for this session",
        )

    record = revocation_records.get(job_id)

    if record is None:
        raise HTTPException(
            status_code=404,
            detail="Revocation record is unavailable",
        )

    return record
