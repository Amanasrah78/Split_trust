import argparse
import asyncio
import base64
import json
import os
import statistics
import time
import uuid
from pathlib import Path
from typing import Any

import httpx

GATEWAY_A_URL = os.getenv(
    "GATEWAY_A_URL",
    "http://gateway-a:8000",
)
SAC_URL = os.getenv("SAC_URL", "http://sac:8000")
GATEWAY_B_URL = os.getenv(
    "GATEWAY_B_URL",
    "http://gateway-b:8000",
)
LEDGER_URL = os.getenv(
    "LEDGER_URL",
    "http://ledger-adapter:8000",
)

def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    if not ordered:
        raise ValueError("Cannot summarize an empty sample")

    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower

    return (
        ordered[lower] * (1 - fraction)
        + ordered[upper] * fraction
    )


def latency_summary(values_ns: list[int]) -> dict[str, float]:
    values_ms = [value / 1_000_000 for value in values_ns]
    return {
        "mean_ms": statistics.fmean(values_ms),
        "median_ms": statistics.median(values_ms),
        "p95_ms": percentile(values_ms, 0.95),
        "p99_ms": percentile(values_ms, 0.99),
        "min_ms": min(values_ms),
        "max_ms": max(values_ms),
    }


def request_body(
    mode: str,
    index: int,
    domains: int = 0,
) -> dict[str, Any]:
    if mode == "e2e":
        return {
            "device_handle": f"actuator-{index % 100}",
            "action": "operate",
            "requested_ttl_seconds": 60,
        }
    if domains >= 2:
        source_index = index % domains
        destination_offset = 1 + (
            (index // domains) % (domains - 1)
        )
        destination_index = (
            source_index + destination_offset
        ) % domains

        gateway_a_did = f"did:iota:gateway-{source_index + 1}"
        gateway_b_did = f"did:iota:gateway-{destination_index + 1}"
    else:
        gateway_a_did = "did:iota:gateway-a"
        gateway_b_did = "did:iota:gateway-b"
    return {
        "trace_id": uuid.uuid4().hex,
        "gateway_a_did": gateway_a_did,
        "gateway_b_did": gateway_b_did,
        "device_handle": f"actuator-{index % 100}",
        "action": "operate",
        "requested_ttl_seconds": 60,
        "nonce_a_b64": base64.b64encode(
            os.urandom(32)
        ).decode("ascii"),
    }


def target_url(mode: str) -> str:
    if mode == "e2e":
        return f"{GATEWAY_A_URL}/sessions"
    return f"{SAC_URL}/authorize"


def retain_response(mode: str, data: dict[str, Any]) -> dict[str, Any]:
    if mode == "e2e":
        return data

    authorization = data.get("authorization", {})
    package = authorization.get("signed_package", {})
    context = package.get("context", {})

    retained = {
        key: value
        for key, value in data.items()
        if key.endswith("_ns")
    }
    retained["session_id"] = context.get("session_id")
    return retained

async def validate_action(
    client: httpx.AsyncClient,
    session_id: str,
) -> tuple[int, str | None]:
    response = await client.post(
        f"{GATEWAY_B_URL}/sessions/{session_id}/validate-action",
        params={"action": "operate"},
    )

    detail: str | None = None

    try:
        body = response.json()
        detail = body.get("detail")
    except Exception:
        pass

    return response.status_code, detail


async def wait_for_revocation_confirmation(
    client: httpx.AsyncClient,
    job_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.05,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        response = await client.get(
            f"{LEDGER_URL}/revocations/{job_id}"
        )
        response.raise_for_status()
        data = response.json()

        if data["status"] == "confirmed":
            return data

        if data["status"] == "failed":
            raise RuntimeError(
                f"Revocation job {job_id} failed: "
                f"{data.get('error')}"
            )

        await asyncio.sleep(poll_interval_seconds)

    raise TimeoutError(
        f"Timed out waiting for revocation job {job_id}"
    )


async def wait_for_rejection(
    client: httpx.AsyncClient,
    session_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.02,
) -> tuple[int, str | None, int]:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        status_code, detail = await validate_action(
            client,
            session_id,
        )

        observed_at_ns = time.time_ns()

        if status_code == 403:
            if detail != "Session has been revoked":
                raise RuntimeError(
                    f"Session {session_id} was rejected for an "
                    f"unexpected reason: {detail!r}"
                )

            return status_code, detail, observed_at_ns

        if status_code != 200:
            raise RuntimeError(
                f"Unexpected validation status "
                f"{status_code} for session {session_id}"
            )

        await asyncio.sleep(poll_interval_seconds)

    raise TimeoutError(
        f"Timed out waiting for session {session_id} rejection"
    )

async def wait_for_session_commitment_confirmation(
    client: httpx.AsyncClient,
    job_id: str,
    timeout_seconds: float,
    poll_interval_seconds: float = 0.05,
) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_seconds

    while time.monotonic() < deadline:
        response = await client.get(
            f"{LEDGER_URL}/commitments/{job_id}"
        )
        response.raise_for_status()

        status = response.json()
        state = status.get("status")

        if state == "confirmed":
            if not status.get("ledger_identifier"):
                raise RuntimeError(
                    f"Confirmed session commitment {job_id} "
                    "has no ledger anchor"
                )
            return status

        if state == "failed":
            raise RuntimeError(
                f"Session commitment {job_id} failed: "
                f"{status.get('error')!r}"
            )

        await asyncio.sleep(poll_interval_seconds)

    raise TimeoutError(
        f"Timed out waiting for session commitment {job_id}"
    )

async def create_revocation_session(
    client: httpx.AsyncClient,
    index: int,
    role: str,
) -> dict[str, Any]:
    response = await client.post(
        f"{GATEWAY_A_URL}/sessions",
        json={
            "device_handle": f"revocation-{role}-{index}",
            "action": "operate",
            "requested_ttl_seconds": 300,
        },
    )
    response.raise_for_status()
    return response.json()


async def issue_revocation_case(
    client: httpx.AsyncClient,
    index: int,
    timeout_seconds: float,
) -> dict[str, Any]:
    case_started_ns = time.perf_counter_ns()

    try:
        # A is the session that will be revoked.
        # B is an independent control session that must remain usable.
        session_a_data = await create_revocation_session(
            client,
            index,
            "revoked",
        )
        session_b_data = await create_revocation_session(
            client,
            index,
            "control",
        )

        session_a = session_a_data["session_id"]
        session_b = session_b_data["session_id"]

        pre_a_status, pre_a_detail = await validate_action(
            client,
            session_a,
        )
        pre_b_status, pre_b_detail = await validate_action(
            client,
            session_b,
        )

        if pre_a_status != 200:
            raise RuntimeError(
                f"Revoked-session candidate {session_a} "
                f"was not usable before revocation: "
                f"{pre_a_status} {pre_a_detail!r}"
            )

        if pre_b_status != 200:
            raise RuntimeError(
                f"Control session {session_b} "
                f"was not usable before revocation: "
                f"{pre_b_status} {pre_b_detail!r}"
            )
        session_a_ledger_job_id = session_a_data.get("ledger_job_id")

        if not session_a_ledger_job_id:
            raise RuntimeError(
                f"Session {session_a} has no ledger commitment job"
            )

        session_anchor_status = (
            await wait_for_session_commitment_confirmation(
                client,
                session_a_ledger_job_id,
                timeout_seconds,
            )
        )

        if session_anchor_status.get("session_id") != session_a:
            raise RuntimeError(
                "Confirmed ledger commitment belongs to a different session"
            )
        revoke_response = await client.post(
            f"{GATEWAY_A_URL}/sessions/{session_a}/revoke",
            params={"reason": "benchmark"},
        )
        revoke_response.raise_for_status()
        revoke_data = revoke_response.json()

        job_id = revoke_data["job_id"]
        requested_wall_clock_ns = int(
            revoke_data["requested_wall_clock_ns"]
        )

        confirmation_task = asyncio.create_task(
            wait_for_revocation_confirmation(
                client,
                job_id,
                timeout_seconds,
            )
        )

        rejection_task = asyncio.create_task(
            wait_for_rejection(
                client,
                session_a,
                timeout_seconds,
            )
        )

        ledger_status, rejection = await asyncio.gather(
            confirmation_task,
            rejection_task,
        )

        (
            rejection_status,
            rejection_detail,
            first_rejection_wall_clock_ns,
        ) = rejection

        confirmed_wall_clock_ns = ledger_status.get(
            "confirmed_wall_clock_ns"
        )

        if not isinstance(confirmed_wall_clock_ns, int):
            raise RuntimeError(
                f"Revocation job {job_id} confirmed without "
                f"a confirmation timestamp"
            )

        control_status, control_detail = await validate_action(
            client,
            session_b,
        )

        reuse_status, reuse_detail = await validate_action(
            client,
            session_a,
        )

        ledger_latency_ns = (
            confirmed_wall_clock_ns
            - requested_wall_clock_ns
        )

        detection_latency_ns = (
            first_rejection_wall_clock_ns
            - confirmed_wall_clock_ns
        )

        total_revocation_latency_ns = (
            first_rejection_wall_clock_ns
            - requested_wall_clock_ns
        )

        return {
            "index": index,
            "ok": True,
            "session_a": session_a,
            "session_b": session_b,
            "revocation_job_id": job_id,
            "requested_wall_clock_ns": requested_wall_clock_ns,
            "confirmed_wall_clock_ns": confirmed_wall_clock_ns,
            "first_rejection_wall_clock_ns": (
                first_rejection_wall_clock_ns
            ),
            "ledger_latency_ns": ledger_latency_ns,
            "detection_latency_ns": detection_latency_ns,
            "total_revocation_latency_ns": (
                total_revocation_latency_ns
            ),
            "ledger_final_ns": ledger_status.get(
                "ledger_final_ns"
            ),
            "pre_revocation_a_status": pre_a_status,
            "pre_revocation_b_status": pre_b_status,
            "rejection_status": rejection_status,
            "rejection_detail": rejection_detail,
            "control_status": control_status,
            "control_detail": control_detail,
            "reuse_status": reuse_status,
            "reuse_detail": reuse_detail,
            "correctly_enforced": (
                rejection_status == 403
                and rejection_detail
                == "Session has been revoked"
            ),
            "control_preserved": control_status == 200,
            "reuse_rejected": (
                reuse_status == 403
                and reuse_detail
                == "Session has been revoked"
            ),
            "case_elapsed_ns": (
                time.perf_counter_ns() - case_started_ns
            ),
        }

    except Exception as exc:
        return {
            "index": index,
            "ok": False,
            "error": str(exc),
            "case_elapsed_ns": (
                time.perf_counter_ns() - case_started_ns
            ),
        }

async def run_revocation(args: argparse.Namespace) -> None:
    limits = httpx.Limits(
        max_connections=max(args.concurrency * 4, 20),
        max_keepalive_connections=max(args.concurrency * 4, 20),
    )

    async with httpx.AsyncClient(
        timeout=args.timeout,
        limits=limits,
    ) as client:
        semaphore = asyncio.Semaphore(args.concurrency)

        async def bounded(index: int) -> dict[str, Any]:
            async with semaphore:
                return await issue_revocation_case(
                    client,
                    index,
                    args.timeout,
                )

        test_started = time.perf_counter_ns()

        results = await asyncio.gather(
            *(bounded(index) for index in range(args.requests))
        )

        test_elapsed_ns = (
            time.perf_counter_ns() - test_started
        )

    successes = [
        item for item in results if item["ok"]
    ]
    failures = [
        item for item in results if not item["ok"]
    ]

    output_directory = Path(args.output_directory)
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    stem = (
        f"revocation-c{args.concurrency}"
        f"-n{args.requests}-{args.run_id}"
    )

    details_path = output_directory / f"{stem}.jsonl"
    summary_path = (
        output_directory / f"{stem}-summary.json"
    )

    with details_path.open(
        "w",
        encoding="utf-8",
    ) as stream:
        for item in results:
            stream.write(
                json.dumps(item, sort_keys=True) + "\n"
            )

    correctly_enforced = sum(
        bool(item["correctly_enforced"])
        for item in successes
    )

    controls_preserved = sum(
        bool(item["control_preserved"])
        for item in successes
    )

    reuse_rejected = sum(
        bool(item["reuse_rejected"])
        for item in successes
    )

    unaffected_session_failures = sum(
        not bool(item["control_preserved"])
        for item in successes
    )

    post_enforcement_reuse_accepts = sum(
        item["reuse_status"] == 200
        for item in successes
    )

    summary: dict[str, Any] = {
        "mode": "revocation",
        "requests": args.requests,
        "warmup": 0,
        "concurrency": args.concurrency,
        "successes": len(successes),
        "failures": len(failures),
        "correctly_enforced": correctly_enforced,
        "controls_preserved": controls_preserved,
        "unaffected_session_failures": (
            unaffected_session_failures
        ),
        "reuse_rejected": reuse_rejected,
        "post_enforcement_reuse_accepts": (
            post_enforcement_reuse_accepts
        ),
        "test_elapsed_seconds": (
            test_elapsed_ns / 1_000_000_000
        ),
        "throughput_cases_per_second": (
            len(successes)
            * 1_000_000_000
            / test_elapsed_ns
        ),
    }

    if successes:
        summary["ledger_latency"] = latency_summary(
            [
                item["ledger_latency_ns"]
                for item in successes
            ]
        )

        summary["observed_detection_latency"] = (
            latency_summary(
                [
                    item["detection_latency_ns"]
                    for item in successes
                ]
            )
        )

        summary["total_revocation_latency"] = (
            latency_summary(
                [
                    item["total_revocation_latency_ns"]
                    for item in successes
                ]
            )
        )

        ledger_final_values = [
            item["ledger_final_ns"]
            for item in successes
            if isinstance(
                item.get("ledger_final_ns"),
                int,
            )
        ]

        if ledger_final_values:
            summary["ledger_finality"] = (
                latency_summary(
                    ledger_final_values
                )
            )

        summary["primary_metric"] = (
            "total_revocation_latency_ns"
        )
        summary["primary_latency"] = summary[
            "total_revocation_latency"
        ]

    summary["all_checks_passed"] = (
        len(failures) == 0
        and correctly_enforced == args.requests
        and controls_preserved == args.requests
        and reuse_rejected == args.requests
    )

    if failures:
        summary["failure_examples"] = failures[:5]

    summary_path.write_text(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )

    print(
        json.dumps(
            summary,
            indent=2,
            sort_keys=True,
        )
    )

async def issue_request(
    client: httpx.AsyncClient,
    mode: str,
    index: int,
    domains: int = 0,
) -> dict[str, Any]:
    started = time.perf_counter_ns()

    try:
        response = await client.post(
            target_url(mode),
            json=request_body(mode, index, domains),
        )
        elapsed_ns = time.perf_counter_ns() - started
        response.raise_for_status()
        data = retain_response(mode, response.json())

        return {
            "index": index,
            "ok": True,
            "client_elapsed_ns": elapsed_ns,
            **data,
        }
    except Exception as exc:
        return {
            "index": index,
            "ok": False,
            "client_elapsed_ns": time.perf_counter_ns() - started,
            "error": f"{type(exc).__name__}: {exc}",
        }


async def run(args: argparse.Namespace) -> None:
    if args.mode == "revocation":
        await run_revocation(args)
        return

    limits = httpx.Limits(
        max_connections=max(args.concurrency, 10),
        max_keepalive_connections=max(args.concurrency, 10),
    )

    async with httpx.AsyncClient(
        timeout=args.timeout,
        limits=limits,
    ) as client:
        for index in range(args.warmup):
            result = await issue_request(
                client,
                args.mode,
                -index - 1,
                args.domains,
            )
            if not result["ok"]:
                raise RuntimeError(
                    f"Warm-up request failed: {result['error']}"
                )

        semaphore = asyncio.Semaphore(args.concurrency)

        async def bounded(index: int) -> dict[str, Any]:
            async with semaphore:
                return await issue_request(
                    client,
                    args.mode,
                    index,
                    args.domains,
                )

        test_started = time.perf_counter_ns()

        results = await asyncio.gather(
            *(bounded(index) for index in range(args.requests))
        )

        test_elapsed_ns = (
            time.perf_counter_ns() - test_started
        )

    successes = [
        item for item in results if item["ok"]
    ]
    failures = [
        item for item in results if not item["ok"]
    ]

    output_directory = Path(args.output_directory)
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    domain_tag = (
        f"-d{args.domains}"
        if args.domains
        else ""
    )

    stem = (
        f"{args.mode}{domain_tag}-c{args.concurrency}-n{args.requests}"
        f"-{args.run_id}"
    )

    details_path = output_directory / f"{stem}.jsonl"
    summary_path = output_directory / f"{stem}-summary.json"

    with details_path.open("w", encoding="utf-8") as stream:
        for item in results:
            stream.write(
                json.dumps(item, sort_keys=True) + "\n"
            )

    summary: dict[str, Any] = {
        "mode": args.mode,
        "requests": args.requests,
        "warmup": args.warmup,
        "concurrency": args.concurrency,
        "domains": args.domains,
        "successes": len(successes),
        "failures": len(failures),
        "test_elapsed_seconds": (
            test_elapsed_ns / 1_000_000_000
        ),
        "throughput_successes_per_second": (
            len(successes)
            * 1_000_000_000
            / test_elapsed_ns
        ),
    }

    if successes:
        summary["client_latency"] = latency_summary(
            [
                item["client_elapsed_ns"]
                for item in successes
            ]
        )

        primary_field = (
            "e2e_ns"
            if args.mode == "e2e"
            else "sac_total_processing_ns"
        )

        summary["primary_metric"] = primary_field
        summary["primary_latency"] = latency_summary(
            [
                item[primary_field]
                for item in successes
            ]
        )

    if failures:
        summary["failure_examples"] = failures[:5]

    summary_path.write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print(json.dumps(summary, indent=2, sort_keys=True))

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--mode",
        choices=("e2e", "sac", "revocation"),
        required=True,
    )
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=1)
    parser.add_argument(
        "--domains",
        type=int,
        default=0,
        help=(
            "Number of registered logical gateway domains for SAC-mode "
            "domain-scaling experiments; 0 preserves the default two-gateway pair"
        ),
    )
    parser.add_argument("--warmup", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--run-id", default="run1")
    parser.add_argument(
        "--output-directory",
        default="/results",
    )
    args = parser.parse_args()

    if args.requests < 1:
        parser.error("--requests must be at least 1")
    if args.concurrency < 1:
        parser.error("--concurrency must be at least 1")
    if args.domains not in (0,) and args.domains < 2:
        parser.error("--domains must be 0 or at least 2")
    if args.domains and args.mode != "sac":
        parser.error("--domains is supported only with --mode sac")
    if args.warmup < 0:
        parser.error("--warmup cannot be negative")

    return args


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
