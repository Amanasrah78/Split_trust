import csv
import json
import math
import statistics
from pathlib import Path

RESULTS = Path("results")
paths = sorted(
    RESULTS.glob("e2e-c1-n1000-run*.jsonl")
)

if len(paths) != 5:
    raise SystemExit(
        f"Expected 5 concurrency-1 trials, found {len(paths)}"
    )

T_CRITICAL = 2.776


def percentile(values: list[float], quantile: float) -> float:
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = int(position)
    upper = min(lower + 1, len(ordered) - 1)
    fraction = position - lower
    return (
        ordered[lower] * (1 - fraction)
        + ordered[upper] * fraction
    )


def mean_ci95(values: list[float]) -> tuple[float, float]:
    mean = statistics.fmean(values)
    ci = (
        T_CRITICAL
        * statistics.stdev(values)
        / math.sqrt(len(values))
    )
    return mean, ci


trial_metrics = []

for path in paths:
    records = [
        json.loads(line)
        for line in path.read_text().splitlines()
        if line.strip()
    ]
    records = [record for record in records if record.get("ok")]

    for record in records:
        record["authorization_verification_combined_ns"] = (
            record["gateway_a_authorization_verification_ns"]
            + record["gateway_b_verification_ns"]
        )

        record["gateway_crypto_core_ns"] = (
            record["gateway_a_total_crypto_ns"]
            - record["gateway_a_authorization_verification_ns"]
            + record["gateway_b_total_crypto_ns"]
        )

        record["gateway_crypto_full_ns"] = (
            record["gateway_a_total_crypto_ns"]
            + record["gateway_b_total_crypto_ns"]
            + record["gateway_b_verification_ns"]
        )
        record["sac_compute_excluding_gb_roundtrip_ns"] = max(
            0,
            record["sac_total_processing_ns"]
            - record["sac_gateway_b_roundtrip_ns"],
        )

    selected = (
        "e2e_ns",
        "authorization_path_ns",
        "sac_total_processing_ns",
        "sac_compute_excluding_gb_roundtrip_ns",
        "gateway_crypto_core_ns",
        "authorization_verification_combined_ns",
        "gateway_crypto_full_ns",
        "gateway_b_handshake_roundtrip_ns",
        "ledger_enqueue_ns",
    )

    trial_metrics.append(
        {
            metric: {
                "mean_ms": statistics.fmean(
                    record[metric] / 1_000_000
                    for record in records
                ),
                "p95_ms": percentile(
                    [
                        record[metric] / 1_000_000
                        for record in records
                    ],
                    0.95,
                ),
            }
            for metric in selected
        }
    )

rows = []

for metric in trial_metrics[0]:
    trial_means = [
        trial[metric]["mean_ms"]
        for trial in trial_metrics
    ]
    trial_p95s = [
        trial[metric]["p95_ms"]
        for trial in trial_metrics
    ]

    mean, mean_ci = mean_ci95(trial_means)
    p95, p95_ci = mean_ci95(trial_p95s)

    rows.append(
        {
            "metric": metric,
            "trials": len(trial_metrics),
            "samples_per_trial": 1000,
            "mean_ms": mean,
            "mean_ci95_ms": mean_ci,
            "p95_ms": p95,
            "p95_ci95_ms": p95_ci,
        }
    )

output = RESULTS / "e2e-c1-component-aggregate.csv"
with output.open("w", newline="", encoding="utf-8") as stream:
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)

print("metric                                      mean ±95% CI       p95 ±95% CI")
for row in rows:
    print(
        f"{row['metric']:<43} "
        f"{row['mean_ms']:>7.4f} "
        f"± {row['mean_ci95_ms']:<7.4f}  "
        f"{row['p95_ms']:>7.4f} "
        f"± {row['p95_ci95_ms']:<7.4f}"
    )
