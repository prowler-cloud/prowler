#!/usr/bin/env python3
import argparse
import re
import subprocess
import sys
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd

plt.style.use("ggplot")


def run_locust(
    locust_file: str,
    host: str,
    users: int,
    hatch_rate: int,
    run_time: str,
    csv_prefix: Path,
) -> Path:
    artifacts_dir = Path("artifacts")
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        "locust",
        "-f",
        f"scenarios/{locust_file}",
        "--headless",
        "-u",
        str(users),
        "-r",
        str(hatch_rate),
        "-t",
        run_time,
        "--host",
        host,
        "--csv",
        str(artifacts_dir / csv_prefix.name),
    ]
    print(f"Running Locust: {' '.join(cmd)}")
    process = subprocess.run(cmd)
    if process.returncode:
        sys.exit("Locust execution failed")

    stats_file = artifacts_dir / f"{csv_prefix.stem}_stats.csv"
    if not stats_file.exists():
        sys.exit(f"Stats CSV not found: {stats_file}")
    return stats_file


def load_percentiles(csv_path: Path) -> pd.DataFrame:
    df = pd.read_csv(csv_path)
    mapping = {"50%": "p50", "75%": "p75", "90%": "p90", "95%": "p95"}
    available = [col for col in mapping if col in df.columns]
    renamed = {col: mapping[col] for col in available}
    df = df.rename(columns=renamed).set_index("Name")[renamed.values()]
    return df.drop(index=["Aggregated"], errors="ignore")


def sanitize_label(label: str) -> str:
    text = re.sub(r"[^\w]+", "_", label.strip().lower())
    return text.strip("_")


def plot_multi_comparison(metrics: dict[str, pd.DataFrame]) -> None:
    common = sorted(set.intersection(*(set(df.index) for df in metrics.values())))
    percentiles = list(next(iter(metrics.values())).columns)
    groups = len(metrics)
    width = 0.8 / groups

    for endpoint in common:
        fig, ax = plt.subplots(figsize=(10, 5), dpi=100)
        for idx, (label, df) in enumerate(metrics.items()):
            series = df.loc[endpoint]
            positions = [
                i + (idx - groups / 2) * width + width / 2
                for i in range(len(percentiles))
            ]
            bars = ax.bar(positions, series.values, width, label=label)
            for bar in bars:
                height = bar.get_height()
                ax.annotate(
                    f"{int(height)}",
                    xy=(bar.get_x() + bar.get_width() / 2, height),
                    xytext=(0, 3),
                    textcoords="offset points",
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

        ax.set_xticks(range(len(percentiles)))
        ax.set_xticklabels(percentiles)
        ax.set_ylabel("Latency (ms)")
        ax.set_title(endpoint, fontsize=12)
        ax.grid(True, axis="y", linestyle="--", alpha=0.7)

        fig.tight_layout()
        fig.subplots_adjust(right=0.75)
        ax.legend(loc="center left", bbox_to_anchor=(1, 0.5), framealpha=0.9)

        output = Path("artifacts") / f"comparison_{sanitize_label(endpoint)}.png"
        plt.savefig(output)
        plt.close(fig)
        print(f"Saved chart: {output}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Run Locust and compare metrics")
    parser.add_argument("--locustfile", required=True, help="Locust file in scenarios/")
    parser.add_argument("--host", required=True, help="Target host URL")
    parser.add_argument(
        "--users", type=int, default=10, help="Number of simulated users"
    )
    parser.add_argument("--rate", type=int, default=1, help="Hatch rate per second")
    parser.add_argument("--time", default="1m", help="Test duration (e.g. 30s, 1m)")
    parser.add_argument(
        "--metrics-dir", default="baselines", help="Directory with CSV baselines"
    )
    args = parser.parse_args()

    metrics_dir = Path(args.metrics_dir)
    if not metrics_dir.is_dir():
        sys.exit(f"Metrics directory not found: {metrics_dir}")

    metrics_data: dict[str, pd.DataFrame] = {}
    for csv_file in sorted(metrics_dir.glob("*.csv")):
        metrics_data[csv_file.stem] = load_percentiles(csv_file)

    current_prefix = Path("current")
    current_csv = run_locust(
        locust_file=args.locustfile,
        host=args.host,
        users=args.users,
        hatch_rate=args.rate,
        run_time=args.time,
        csv_prefix=current_prefix,
    )
    metrics_data["current"] = load_percentiles(current_csv)

    for endpoint in sorted(
        set.intersection(*(set(df.index) for df in metrics_data.values()))
    ):
        parts = [endpoint]
        for label, df in metrics_data.items():
            s = df.loc[endpoint]
            parts.append(f"{label}: p50 {s.p50}, p75 {s.p75}, p90 {s.p90}, p95 {s.p95}")
        print(" | ".join(parts))

    plot_multi_comparison(metrics_data)


if __name__ == "__main__":
    main()
