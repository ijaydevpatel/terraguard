"""How much the model scores move when only the fold assignment changes.

Adding the live observations on 16 Oct brought in six new scenario templates and moved
Logistic Regression from 0.7789 to 0.7324 macro F1 and Random Forest from 0.8198 to 0.8874 at
the fixed seed, and the repeat runs moved them again.
The old data still reproduces the old figures exactly, so the pipeline is deterministic. What
changed is which templates share a fold. With 3 grouped splits that matters, and a single
split cannot show by how much.

This repeats the grouped cross-validation under 20 split seeds, holding the model seed fixed,
and reports the spread. Writes results/fold_stability.json and results/fold_stability.md.

    python scripts/fold_stability.py
"""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
sys.path.insert(0, str(ROOT))

SEEDS = range(20)


def main() -> int:
    from sklearn.metrics import f1_score

    from terraguard.feature_builder import build_matrix, groups_for, load_rows
    from terraguard.model_trainer import (
        MIN_GROUPS,
        RANDOM_STATE,
        _cross_val_predict,
        _fresh_models,
        labels_for,
    )

    rows = load_rows(ROOT / "datasets/findings.csv", ROOT / "datasets/observations.csv")
    y = labels_for(rows)
    groups = groups_for(rows)
    records, _ = build_matrix(rows)

    scores: dict[str, list[float]] = {"logistic_regression": [], "random_forest": []}
    rf_ahead = 0
    for seed in SEEDS:
        logistic, forest = _fresh_models()
        per_seed = {}
        for name, model in (("logistic_regression", logistic), ("random_forest", forest)):
            y_true, y_pred, _ = _cross_val_predict(model, records, y, groups, MIN_GROUPS, seed)
            per_seed[name] = round(float(f1_score(y_true, y_pred, average="macro")), 4)
            scores[name].append(per_seed[name])
        rf_ahead += per_seed["random_forest"] > per_seed["logistic_regression"]

    summary = {
        "n_findings": len(rows),
        "n_groups": len(set(groups)),
        "n_splits": MIN_GROUPS,
        "split_seeds": len(SEEDS),
        "model_seed": RANDOM_STATE,
        "random_forest_ahead": rf_ahead,
        "macro_f1": {
            name: {
                "mean": round(statistics.mean(v), 4),
                "sd": round(statistics.stdev(v), 4),
                "min": min(v),
                "max": max(v),
                "per_seed": v,
            }
            for name, v in scores.items()
        },
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "fold_stability.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")

    lines = [
        "# Fold stability",
        "",
        f"{summary['n_findings']} findings, {summary['n_groups']} templates, "
        f"{MIN_GROUPS} grouped splits, {len(SEEDS)} split seeds, model seed fixed.",
        "",
        "| Model | Mean macro F1 | SD | Min | Max |",
        "|---|---:|---:|---:|---:|",
    ]
    for name, s in summary["macro_f1"].items():
        lines.append(f"| {name} | {s['mean']} | {s['sd']} | {s['min']} | {s['max']} |")
    lines += [
        "",
        f"Random Forest scored higher on {rf_ahead} of {len(SEEDS)} split seeds.",
        "",
        f"model_comparison.md uses one further split seed ({RANDOM_STATE}). Quote the range",
        "here, not that single value.",
        "",
    ]
    (RESULTS / "fold_stability.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
