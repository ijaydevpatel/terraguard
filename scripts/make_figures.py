"""Build the figure set for the results chapter from the committed results.

Every figure is regenerated from `results/` and `datasets/`, so none of them can drift away
from the numbers in the text. Matplotlib defaults only: no seaborn, no styling that would
need another dependency at submission time.

    python scripts/make_figures.py
"""

from __future__ import annotations

import csv
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
FIGURES = ROOT / "results" / "figures"
BANDS = ["high_or_critical", "medium", "non_security_or_low"]
SHORT = {"high_or_critical": "high/crit", "medium": "medium", "non_security_or_low": "non-sec/low"}


def confusion(report: dict) -> None:
    for score in report["scores"]:
        if score["name"] == "deterministic_rules" or not score["confusion"]:
            continue
        matrix = score["confusion"]
        fig, ax = plt.subplots(figsize=(4.5, 4))
        ax.imshow(matrix, cmap="Blues")
        ax.set_xticks(range(len(BANDS)), [SHORT[b] for b in report["labels"]], rotation=30)
        ax.set_yticks(range(len(BANDS)), [SHORT[b] for b in report["labels"]])
        for i, row in enumerate(matrix):
            for j, value in enumerate(row):
                ax.text(
                    j,
                    i,
                    str(value),
                    ha="center",
                    va="center",
                    color="white" if value > max(max(r) for r in matrix) / 2 else "black",
                )
        ax.set_xlabel("predicted")
        ax.set_ylabel("actual")
        ax.set_title(f"{score['name']} (macro F1 {score['macro_f1']})")
        fig.tight_layout()
        fig.savefig(FIGURES / f"confusion_{score['name']}.png", dpi=200)
        plt.close(fig)


def importances(report: dict) -> None:
    items = list(report["importances"].items())[:10][::-1]
    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.barh([k for k, _ in items], [v for _, v in items])
    ax.set_xlabel("Random Forest importance")
    ax.set_title("What the model leans on")
    fig.tight_layout()
    fig.savefig(FIGURES / "feature_importances.png", dpi=200)
    plt.close(fig)


def class_support(report: dict) -> None:
    fig, ax = plt.subplots(figsize=(6, 3.6))
    x = range(len(report["labels"]))
    findings = [report["class_support"].get(b, 0) for b in report["labels"]]
    groups = [report["groups_per_class"].get(b, 0) for b in report["labels"]]
    ax.bar([i - 0.2 for i in x], findings, width=0.4, label="findings")
    ax.bar([i + 0.2 for i in x], groups, width=0.4, label="independent templates")
    ax.set_xticks(list(x), [SHORT[b] for b in report["labels"]])
    ax.set_yscale("log")
    ax.set_ylabel("count (log scale)")
    ax.set_title("Class support: rows against groups")
    ax.legend()
    fig.tight_layout()
    fig.savefig(FIGURES / "class_support.png", dpi=200)
    plt.close(fig)


def leakage() -> None:
    data = json.loads((RESULTS / "leakage_matrix.json").read_text(encoding="utf-8"))
    labels = ["grouped", "ungrouped"]
    without = [
        data["grouped_without_rule_inputs"]["macro_f1"],
        data["ungrouped_without_rule_inputs"]["macro_f1"],
    ]
    with_ = [
        data["grouped_with_rule_inputs"]["macro_f1"],
        data["ungrouped_with_rule_inputs"]["macro_f1"],
    ]
    fig, ax = plt.subplots(figsize=(5.5, 3.6))
    x = range(len(labels))
    ax.bar([i - 0.2 for i in x], without, width=0.4, label="rule inputs withheld")
    ax.bar([i + 0.2 for i in x], with_, width=0.4, label="rule inputs included")
    ax.set_xticks(list(x), labels)
    ax.set_ylim(0, 1.05)
    ax.set_ylabel("macro F1")
    ax.set_title("Leakage: both defences are doing work")
    ax.legend(fontsize=8)
    fig.tight_layout()
    fig.savefig(FIGURES / "leakage_matrix.png", dpi=200)
    plt.close(fig)


def timing() -> None:
    rows = list(csv.DictReader(open(ROOT / "datasets/observations.csv", encoding="utf-8")))
    by_source: dict[str, list[float]] = {}
    for r in rows:
        by_source.setdefault(r["evidence_source"].split(",")[0], []).append(
            float(r["processing_time_ms"])
        )
    keys = sorted(by_source, key=lambda k: -len(by_source[k]))[:5]
    fig, ax = plt.subplots(figsize=(6.5, 3.8))
    ax.boxplot([by_source[k] for k in keys], tick_labels=[k[:18] for k in keys])
    ax.set_ylabel("processing time (ms)")
    ax.set_title("Processing time by evidence source")
    plt.xticks(rotation=20)
    fig.tight_layout()
    fig.savefig(FIGURES / "processing_time.png", dpi=200)
    plt.close(fig)


def coverage() -> None:
    rows = list(csv.DictReader(open(ROOT / "datasets/observations.csv", encoding="utf-8")))
    values = [float(r["assessment_coverage"]) for r in rows]
    fig, ax = plt.subplots(figsize=(6, 3.6))
    ax.hist(values, bins=20)
    ax.set_xlabel("assessment coverage")
    ax.set_ylabel("runs")
    ax.set_title("Coverage: how much of the catalogue each run could answer")
    fig.tight_layout()
    fig.savefig(FIGURES / "assessment_coverage.png", dpi=200)
    plt.close(fig)


def main() -> int:
    FIGURES.mkdir(parents=True, exist_ok=True)
    report = json.loads((RESULTS / "training_report.json").read_text(encoding="utf-8"))
    confusion(report)
    importances(report)
    class_support(report)
    leakage()
    timing()
    coverage()
    written = sorted(p.name for p in FIGURES.glob("*.png"))
    print(f"{len(written)} figures in {FIGURES}")
    for name in written:
        print(f"  {name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
