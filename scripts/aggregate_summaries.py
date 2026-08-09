import argparse
import csv
import json
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("e2e", "sac"))
    parser.add_argument(
        "--results-directory",
        type=Path,
        default=Path("results"),
    )
    args = parser.parse_args()

    paths = sorted(
        args.results_directory.glob(
            f"{args.mode}-c*-n*-summary.json"
        )
    )
    if not paths:
        raise SystemExit(f"No {args.mode!r} summary files found")

    rows = []
    for path in paths:
        data = json.loads(path.read_text())
        primary = data.get("primary_latency", {})
        client = data.get("client_latency", {})

        rows.append(
            {
                "concurrency": data["concurrency"],
                "requests": data["requests"],
                "successes": data["successes"],
                "failures": data["failures"],
                "throughput_per_second": (
                    data["throughput_successes_per_second"]
                ),
                "internal_mean_ms": primary.get("mean_ms"),
                "internal_median_ms": primary.get("median_ms"),
                "internal_p95_ms": primary.get("p95_ms"),
                "internal_p99_ms": primary.get("p99_ms"),
                "client_mean_ms": client.get("mean_ms"),
                "client_p95_ms": client.get("p95_ms"),
            }
        )

    rows.sort(key=lambda row: row["concurrency"])
    output = (
        args.results_directory
        / f"{args.mode}-scalability.csv"
    )

    with output.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(
            stream,
            fieldnames=list(rows[0]),
        )
        writer.writeheader()
        writer.writerows(rows)

    print(
        "concurrency  throughput/s  internal mean  internal p95  failures"
    )
    for row in rows:
        print(
            f"{row['concurrency']:>11}  "
            f"{row['throughput_per_second']:>12.2f}  "
            f"{row['internal_mean_ms']:>13.3f}  "
            f"{row['internal_p95_ms']:>12.3f}  "
            f"{row['failures']:>8}"
        )


if __name__ == "__main__":
    main()
