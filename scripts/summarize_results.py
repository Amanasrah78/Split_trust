import argparse
import csv
import json
import statistics
from pathlib import Path


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


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("input", type=Path)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("results/metric-breakdown.csv"),
    )
    args = parser.parse_args()

    records = [
        json.loads(line)
        for line in args.input.read_text().splitlines()
        if line.strip()
    ]
    records = [record for record in records if record.get("ok")]

    if not records:
        raise SystemExit("No successful records were found")

    for record in records:
        if (
            "gateway_a_total_crypto_ns" in record
            and "gateway_b_total_crypto_ns" in record
        ):
            record["gateway_crypto_combined_ns"] = (
                record["gateway_a_total_crypto_ns"]
                + record["gateway_b_total_crypto_ns"]
            )

        if (
            "authorization_path_ns" in record
            and "sac_total_processing_ns" in record
        ):
            record["authorization_transport_overhead_ns"] = max(
                0,
                record["authorization_path_ns"]
                - record["sac_total_processing_ns"],
            )

        if (
            "gateway_b_handshake_roundtrip_ns" in record
            and "gateway_b_total_crypto_ns" in record
        ):
            record["handshake_transport_overhead_ns"] = max(
                0,
                record["gateway_b_handshake_roundtrip_ns"]
                - record["gateway_b_total_crypto_ns"],
            )

    metric_names = sorted(
        {
            key
            for record in records
            for key, value in record.items()
            if key.endswith("_ns")
            and isinstance(value, int)
        }
    )

    rows = []
    for metric in metric_names:
        values_ns = [
            record[metric]
            for record in records
            if metric in record
        ]
        values_ms = [value / 1_000_000 for value in values_ns]

        rows.append(
            {
                "metric": metric,
                "samples": len(values_ms),
                "mean_ms": statistics.fmean(values_ms),
                "stdev_ms": (
                    statistics.stdev(values_ms)
                    if len(values_ms) > 1
                    else 0.0
                ),
                "median_ms": statistics.median(values_ms),
                "p95_ms": percentile(values_ms, 0.95),
                "p99_ms": percentile(values_ms, 0.99),
                "min_ms": min(values_ms),
                "max_ms": max(values_ms),
            }
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(rows[0]),
        )
        writer.writeheader()
        writer.writerows(rows)

    for row in rows:
        print(
            f"{row['metric']:<42} "
            f"mean={row['mean_ms']:>9.6f} ms  "
            f"p95={row['p95_ms']:>9.6f} ms"
        )


if __name__ == "__main__":
    main()
