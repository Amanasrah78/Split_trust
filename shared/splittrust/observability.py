import json
import time
import uuid
from typing import Any


def new_trace_id() -> str:
    return uuid.uuid4().hex


def monotonic_ns() -> int:
    return time.perf_counter_ns()


def wall_clock_ns() -> int:
    return time.time_ns()


def ns_to_ms(value: int) -> float:
    return round(value / 1_000_000, 6)


def log_event(
    service: str,
    event: str,
    trace_id: str,
    **fields: Any,
) -> None:
    record = {
        "wall_clock_ns": wall_clock_ns(),
        "service": service,
        "event": event,
        "trace_id": trace_id,
        **fields,
    }
    print(json.dumps(record, sort_keys=True), flush=True)
