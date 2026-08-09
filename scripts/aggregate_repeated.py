import argparse
import csv
import json
import math
import re
import statistics
from collections import defaultdict
from pathlib import Path

RESULTS = Path("results")

T_CRITICAL_95 = {
    1: 12.706,
    2: 4.303,
    3: 3.182,
    4: 2.776,
    5: 2.571,
    6: 2.447,
    7: 2.365,
    8: 2.306,
    9: 2.262,
}


def mean_and_ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.fmean(values)
    if len(values) < 2:
        return mean, 0.0

    degrees_of_freedom = len(values) - 1
    critical = T_CRITICAL_95.get(degrees_of_freedom, 1.96)
    standard_error = statistics.stdev(values) / math.sqrt(len(values))
    return mean, critical * standard_error


parser = argparse.ArgumentParser()
parser.add_argument("mode", choices=("e2e", "sac"))
args = parser.parse_args()

pattern = re.compile(
    rf"{args.mode}-c(?P<concurrency>\d+)-n(?P<requests>\d+)"
    r"-run(?P<run>\d+)-summary\.json"
)

grouped: dict[int, list[dict]] = defaultdict(list)

for path in RESULTS.glob(
    f"{args.mode}-c*-n*-run*-summary.json"
):
    match = pattern.fullmatch(path.name)
    if match:
        data = json.loads(path.read_text())
        data["_path"] = str(path)
        grouped[int(match.group("concurrency"))].append(data)

if not grouped:
    raise SystemExit(
        f"No repeated {args.mode.upper()} summary files were found"
    )

rows = []

for concurrency, trials in sorted(grouped.items()):
    trials.sort(key=lambda item: item["_path"])

    throughput = [
        trial["throughput_successes_per_second"]
        for trial in trials
    ]
    client_mean = [
        trial["client_latency"]["mean_ms"]
        for trial in trials
    ]
    client_p95 = [
        trial["client_latency"]["p95_ms"]
        for trial in trials
    ]
    client_p99 = [
        trial["client_latency"]["p99_ms"]
        for trial in trials
    ]
    internal_mean = [
        trial["primary_latency"]["mean_ms"]
        for trial in trials
    ]
    internal_p95 = [
        trial["primary_latency"]["p95_ms"]
        for trial in trials
    ]

    throughput_mean, throughput_ci = mean_and_ci95(throughput)
    client_mean_mean, client_mean_ci = mean_and_ci95(client_mean)
    client_p95_mean, client_p95_ci = mean_and_ci95(client_p95)
    client_p99_mean, client_p99_ci = mean_and_ci95(client_p99)
    internal_mean_mean, internal_mean_ci = mean_and_ci95(
        internal_mean
    )
    internal_p95_mean, internal_p95_ci = mean_and_ci95(
        internal_p95
    )

    rows.append(
        {
            "concurrency": concurrency,
            "trials": len(trials),
            "requests_per_trial": trials[0]["requests"],
            "total_successes": sum(
                trial["successes"] for trial in trials
            ),
            "total_failures": sum(
                trial["failures"] for trial in trials
            ),
            "throughput_mean_per_s": throughput_mean,
            "throughput_ci95_per_s": throughput_ci,
            "client_mean_ms": client_mean_mean,
            "client_mean_ci95_ms": client_mean_ci,
            "client_p95_ms": client_p95_mean,
            "client_p95_ci95_ms": client_p95_ci,
            "client_p99_ms": client_p99_mean,
            "client_p99_ci95_ms": client_p99_ci,
            "internal_mean_ms": internal_mean_mean,
            "internal_mean_ci95_ms": internal_mean_ci,
            "internal_p95_ms": internal_p95_mean,
            "internal_p95_ci95_ms": internal_p95_ci,
        }
    )

output = RESULTS / f"{args.mode}-repeated-aggregate.csv"
with output.open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print(
    "conc trials failures  throughput ±95% CI      "
    "client mean ±95% CI    client p95 ±95% CI"
)
for row in rows:
    print(
        f"{row['concurrency']:>4} "
        f"{row['trials']:>6} "
        f"{row['total_failures']:>8}  "
        f"{row['throughput_mean_per_s']:>8.2f} "
        f"± {row['throughput_ci95_per_s']:<8.2f}  "
        f"{row['client_mean_ms']:>8.3f} "
        f"± {row['client_mean_ci95_ms']:<7.3f}  "
        f"{row['client_p95_ms']:>8.3f} "
        f"± {row['client_p95_ci95_ms']:<7.3f}"
    )
