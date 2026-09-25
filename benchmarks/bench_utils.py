"""Shared helpers for the benchmark scripts: paths, CSV output, summary and plotting."""
from __future__ import annotations

import platform
import sys
from pathlib import Path

import matplotlib

matplotlib.use("Agg")  # write PNG files without opening windows
import matplotlib.pyplot as plt  # noqa: E402
import pandas as pd  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "benchmarks" / "results"
GRAPHS = ROOT / "benchmarks" / "graphs"
RESULTS.mkdir(parents=True, exist_ok=True)
GRAPHS.mkdir(parents=True, exist_ok=True)


def environment() -> str:
    return f"{platform.system()} {platform.release()}, {platform.processor() or platform.machine()}, Python {sys.version.split()[0]}"


def save_raw_and_summary(rows, name: str, group: str = "n_devices") -> pd.DataFrame:
    raw = pd.DataFrame(rows)
    raw.to_csv(RESULTS / f"{name}_raw.csv", index=False)
    numeric = raw.drop(columns=["run"], errors="ignore")
    summary = numeric.groupby(group).agg(["mean", "std"])
    summary.columns = [f"{a}_{b}" for a, b in summary.columns]
    summary = summary.reset_index()
    summary.to_csv(RESULTS / f"{name}_summary.csv", index=False)
    return summary


def line_plot(summary: pd.DataFrame, series, title: str, ylabel: str, filename: str,
              xlabel: str = "Number of devices", logy: bool = False, logx: bool = False) -> Path:
    """series: list of (column_prefix, label). Uses <prefix>_mean and <prefix>_std."""
    fig, ax = plt.subplots(figsize=(7, 4.5))
    for col, label in series:
        ax.errorbar(summary["n_devices"], summary[f"{col}_mean"], yerr=summary[f"{col}_std"].fillna(0),
                    marker="o", capsize=4, linewidth=1.8, label=label)
    ax.set_title(title)
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    if logy:
        ax.set_yscale("log")
    if logx:
        ax.set_xscale("log")
    ax.grid(True, alpha=0.3)
    if len(series) > 1:
        ax.legend()
    fig.tight_layout()
    out = GRAPHS / filename
    fig.savefig(out, dpi=160)
    plt.close(fig)
    return out