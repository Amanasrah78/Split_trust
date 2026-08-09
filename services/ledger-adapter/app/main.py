import asyncio
import os
import uuid
from contextlib import asynccontextmanager, suppress

from fastapi import FastAPI, HTTPException, status

from shared.splittrust.encoding import b64decode
from shared.splittrust.models import (
    LedgerCommitAccepted,
    LedgerCommitRequest,
    LedgerCommitStatus,
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

if len(b64decode(LEDGER_EPOCH_DIGEST_B64)) != 32:
    raise RuntimeError("LEDGER_EPOCH_DIGEST_B64 must decode to 32 bytes")

queue: asyncio.Queue[tuple[str, LedgerCommitRequest]] = asyncio.Queue()
records: dict[str, LedgerCommitStatus] = {}
started_ns: dict[str, int] = {}


async def commitment_worker() -> None:
    while True:
        job_id, request = await queue.get()

        try:
            record = records[job_id]
            record.status = "submitting"

            if LEDGER_MODE != "simulated":
                raise RuntimeError(
                    f"Ledger mode {LEDGER_MODE!r} is not implemented yet"
                )

            await asyncio.sleep(SIMULATED_FINALITY_MS / 1000)

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
                session_usable_wall_clock_ns=(
                    request.session_usable_wall_clock_ns
                ),
            )
        except Exception as exc:
            record = records[job_id]
            record.status = "failed"
            record.error = str(exc)

            log_event(
                SERVICE,
                "commitment_failed",
                request.trace_id,
                job_id=job_id,
                session_id=request.session_id,
                error=str(exc),
            )
        finally:
            queue.task_done()


@asynccontextmanager
async def lifespan(_: FastAPI):
    workers = [
        asyncio.create_task(commitment_worker())
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

    job_id = uuid.uuid4().hex
    queued_at = wall_clock_ns()

    records[job_id] = LedgerCommitStatus(
        job_id=job_id,
        session_id=request.session_id,
        status="queued",
        queued_wall_clock_ns=queued_at,
    )
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
