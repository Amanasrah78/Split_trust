import argparse
import csv
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path

RESULTS = Path("results")
PATTERN = re.compile(
    r"e2e-c1-n(?P<requests>\d+)-delay-(?P<delay>\d+)ms-"
    r"run(?P<run>\d+)-summary\.json"
)
T_CRITICAL_95 = {1: 12.706, 2: 4.303, 3: 3.182, 4: 2.776}


def mean_ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.fmean(values)
    if len(values) < 2:
        return mean, 0.0
    critical = T_CRITICAL_95.get(len(values) - 1, 1.96)
    return mean, critical * statistics.stdev(values) / math.sqrt(len(values))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--requests", type=int)
    args = parser.parse_args()

    grouped: dict[int, list[dict]] = defaultdict(list)
    for path in RESULTS.glob("e2e-c1-n*-delay-*ms-run*-summary.json"):
        match = PATTERN.fullmatch(path.name)
        if match and (
            args.requests is None
            or int(match.group("requests")) == args.requests
        ):
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_requests"] = int(match.group("requests"))
            data["_run"] = int(match.group("run"))
            grouped[int(match.group("delay"))].append(data)

    if not grouped:
        raise SystemExit("No delay-matrix summaries were found")

    rows = []
    for delay_ms, trials in sorted(grouped.items()):
        trials.sort(key=lambda item: item["_run"])
        request_counts = {item["_requests"] for item in trials}
        if len(request_counts) != 1:
            raise SystemExit(f"Delay {delay_ms} ms mixes request counts")

        means = [item["primary_latency"]["mean_ms"] for item in trials]
        p95s = [item["primary_latency"]["p95_ms"] for item in trials]
        mean_ms, mean_ci = mean_ci95(means)
        p95_ms, p95_ci = mean_ci95(p95s)
        rows.append(
            {
                "one_way_delay_ms": delay_ms,
                "trials": len(trials),
                "requests_per_trial": trials[0]["_requests"],
                "total_successes": sum(x["successes"] for x in trials),
                "total_failures": sum(x["failures"] for x in trials),
                "e2e_mean_ms": mean_ms,
                "e2e_mean_ci95_ms": mean_ci,
                "e2e_p95_ms": p95_ms,
                "e2e_p95_ci95_ms": p95_ci,
            }
        )

    output_name = (
        "delay-matrix-aggregate.csv"
        if args.requests in (None, 1000)
        else f"delay-matrix-n{args.requests}-aggregate.csv"
    )
    output = RESULTS / output_name
    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(
            f"d={row['one_way_delay_ms']:>2} ms  "
            f"mean={row['e2e_mean_ms']:.3f} ± "
            f"{row['e2e_mean_ci95_ms']:.3f} ms  "
            f"p95={row['e2e_p95_ms']:.3f} ± "
            f"{row['e2e_p95_ci95_ms']:.3f} ms"
        )


if __name__ == "__main__":
    main()
