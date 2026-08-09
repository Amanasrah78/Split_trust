import csv
from pathlib import Path

RESULTS = Path("results")


def read_rows(filename):
    with (RESULTS / filename).open(newline="") as stream:
        return list(csv.DictReader(stream))


components = {
    row["metric"]: row
    for row in read_rows("e2e-c1-component-aggregate.csv")
}
e2e_rows = read_rows("e2e-repeated-aggregate.csv")
sac_rows = read_rows("sac-repeated-aggregate.csv")

component_labels = [
    ("gateway_crypto_full_ns", r"Gateway cryptographic processing"),
    ("authorization_path_ns", r"SAC authorization path"),
    ("e2e_ns", r"Authorization-to-usable-session E2E"),
    ("ledger_enqueue_ns", r"Post-usability ledger enqueue"),
]

lines = [
    r"% Generated from the final Docker testbed datasets.",
    r"% Ledger finality is simulated and is intentionally omitted.",
    "",
    r"\begin{table}[t]",
    r"\centering",
    r"\caption{Latency scopes at concurrency 1 over five trials of 1,000 measured sessions each.}",
    r"\label{tab:docker-latency-scopes}",
    r"\begin{tabular}{lcc}",
    r"\hline",
    r"\textbf{Metric} & \textbf{Mean $\pm$ 95\% CI (ms)} & \textbf{p95 $\pm$ 95\% CI (ms)} \\",
    r"\hline",
]

for key, label in component_labels:
    row = components[key]
    lines.append(
        f"{label} & "
        f"{float(row['mean_ms']):.4f} $\\pm$ "
        f"{float(row['mean_ci95_ms']):.4f} & "
        f"{float(row['p95_ms']):.4f} $\\pm$ "
        f"{float(row['p95_ci95_ms']):.4f} \\\\"
    )

lines.extend(
    [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
        "",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{SAC-inclusive E2E scalability over five repeated trials per concurrency level.}",
        r"\label{tab:docker-e2e-scalability}",
        r"\begin{tabular}{rccc}",
        r"\hline",
        r"\textbf{Concurrency} & \textbf{Throughput (s$^{-1}$)} & \textbf{Mean E2E (ms)} & \textbf{p95 E2E (ms)} \\",
        r"\hline",
    ]
)

for row in sorted(e2e_rows, key=lambda item: int(item["concurrency"])):
    lines.append(
        f"{int(row['concurrency'])} & "
        f"{float(row['throughput_mean_per_s']):.2f} "
        f"$\\pm$ {float(row['throughput_ci95_per_s']):.2f} & "
        f"{float(row['internal_mean_ms']):.3f} "
        f"$\\pm$ {float(row['internal_mean_ci95_ms']):.3f} & "
        f"{float(row['internal_p95_ms']):.3f} "
        f"$\\pm$ {float(row['internal_p95_ci95_ms']):.3f} \\\\"
    )

lines.extend(
    [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
        "",
        r"\begin{table}[t]",
        r"\centering",
        r"\caption{SAC authorization scalability over five trials of 2,000 measured requests per concurrency level.}",
        r"\label{tab:docker-sac-scalability}",
        r"\begin{tabular}{rccc}",
        r"\hline",
        r"\textbf{Concurrency} & \textbf{Throughput (s$^{-1}$)} & \textbf{Client mean (ms)} & \textbf{Client p95 (ms)} \\",
        r"\hline",
    ]
)

for row in sorted(sac_rows, key=lambda item: int(item["concurrency"])):
    lines.append(
        f"{int(row['concurrency'])} & "
        f"{float(row['throughput_mean_per_s']):.2f} "
        f"$\\pm$ {float(row['throughput_ci95_per_s']):.2f} & "
        f"{float(row['client_mean_ms']):.3f} "
        f"$\\pm$ {float(row['client_mean_ci95_ms']):.3f} & "
        f"{float(row['client_p95_ms']):.3f} "
        f"$\\pm$ {float(row['client_p95_ci95_ms']):.3f} \\\\"
    )

lines.extend(
    [
        r"\hline",
        r"\end{tabular}",
        r"\end{table}",
        "",
    ]
)

output = RESULTS / "manuscript-results.tex"
output.write_text("\n".join(lines))
print(output)
