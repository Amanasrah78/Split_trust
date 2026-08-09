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


def request_body(mode: str, index: int) -> dict[str, Any]:
    if mode == "e2e":
        return {
            "device_handle": f"actuator-{index % 100}",
            "action": "operate",
            "requested_ttl_seconds": 60,
        }

    return {
        "trace_id": uuid.uuid4().hex,
        "gateway_a_did": "did:iota:gateway-a",
        "gateway_b_did": "did:iota:gateway-b",
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


async def issue_request(
    client: httpx.AsyncClient,
    mode: str,
    index: int,
) -> dict[str, Any]:
    started = time.perf_counter_ns()

    try:
        response = await client.post(
            target_url(mode),
            json=request_body(mode, index),
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
            "error": str(exc),
        }


async def run(args: argparse.Namespace) -> None:
    limits = httpx.Limits(
        max_connections=max(args.concurrency, 10),
        max_keepalive_connections=max(args.concurrency, 10),
    )

    async with httpx.AsyncClient(
        timeout=args.timeout,
        limits=limits,
    ) as client:
        for index in range(args.warmup):
            result = await issue_request(client, args.mode, -index - 1)
            if not result["ok"]:
                raise RuntimeError(
                    f"Warm-up request failed: {result['error']}"
                )

        semaphore = asyncio.Semaphore(args.concurrency)

        async def bounded(index: int) -> dict[str, Any]:
            async with semaphore:
                return await issue_request(client, args.mode, index)

        test_started = time.perf_counter_ns()
        results = await asyncio.gather(
            *(bounded(index) for index in range(args.requests))
        )
        test_elapsed_ns = time.perf_counter_ns() - test_started

    successes = [item for item in results if item["ok"]]
    failures = [item for item in results if not item["ok"]]

    output_directory = Path(args.output_directory)
    output_directory.mkdir(parents=True, exist_ok=True)

    stem = (
        f"{args.mode}-c{args.concurrency}-n{args.requests}"
        f"-{args.run_id}"
    )
    details_path = output_directory / f"{stem}.jsonl"
    summary_path = output_directory / f"{stem}-summary.json"

    with details_path.open("w", encoding="utf-8") as stream:
        for item in results:
            stream.write(json.dumps(item, sort_keys=True) + "\n")

    summary: dict[str, Any] = {
        "mode": args.mode,
        "requests": args.requests,
        "warmup": args.warmup,
        "concurrency": args.concurrency,
        "successes": len(successes),
        "failures": len(failures),
        "test_elapsed_seconds": test_elapsed_ns / 1_000_000_000,
        "throughput_successes_per_second": (
            len(successes) * 1_000_000_000 / test_elapsed_ns
        ),
    }

    if successes:
        summary["client_latency"] = latency_summary(
            [item["client_elapsed_ns"] for item in successes]
        )

        primary_field = (
            "e2e_ns"
            if args.mode == "e2e"
            else "sac_total_processing_ns"
        )
        summary["primary_metric"] = primary_field
        summary["primary_latency"] = latency_summary(
            [item[primary_field] for item in successes]
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
        choices=("e2e", "sac"),
        required=True,
    )
    parser.add_argument("--requests", type=int, default=100)
    parser.add_argument("--concurrency", type=int, default=1)
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
    if args.warmup < 0:
        parser.error("--warmup cannot be negative")

    return args


if __name__ == "__main__":
    asyncio.run(run(parse_args()))
