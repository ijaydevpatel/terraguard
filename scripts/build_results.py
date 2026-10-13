"""Regenerate every result artefact in results/ from the committed dataset.

This is the pipeline, not scaffolding. Given `datasets/findings.csv` and
`datasets/observations.csv` it reproduces the whole of the W8/W9 analysis: the model
comparison, the leakage matrix, the split verification, the data-quality pass and the
encoder.

Everything it writes to `results/` is committed, because the tracker and the methodology
notes cite those files as evidence and a reader must be able to open them. The encoder is a
pickle and stays in `build/`, which is ignored - consistent with `models/*.joblib` already
being ignored.

    python scripts/build_results.py
"""

from __future__ import annotations

import csv
import json
import pickle
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
BUILD = ROOT / "build"
sys.path.insert(0, str(ROOT))


def main() -> int:
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.model_selection import StratifiedGroupKFold, StratifiedKFold
    from sklearn.pipeline import make_pipeline

    from terraguard.feature_builder import build_leaky_matrix, build_matrix, groups_for, load_rows
    from terraguard.model_trainer import (
        RANDOM_STATE,
        _fresh_models,
        _score,
        labels_for,
        run_comparison,
    )

    RESULTS.mkdir(exist_ok=True)
    BUILD.mkdir(exist_ok=True)
    findings_csv = ROOT / "datasets/findings.csv"
    observations_csv = ROOT / "datasets/observations.csv"

    # ---- data quality -------------------------------------------------------------
    findings = list(csv.DictReader(open(findings_csv, encoding="utf-8")))
    observations = list(csv.DictReader(open(observations_csv, encoding="utf-8")))
    pairs = Counter((f["run_id"], f["finding_id"]) for f in findings)
    duplicates = [
        {"run_id": run_id, "finding_id": finding_id, "count": count}
        for (run_id, finding_id), count in pairs.items()
        if count > 1
    ]
    quality = {
        "findings": len(findings),
        "observations": len(observations),
        "duplicate_id_pairs": len(duplicates),
        "orphan_runs": sorted(
            {f["run_id"] for f in findings} - {o["run_id"] for o in observations}
        ),
        "blank_required_fields": {
            column: sum(1 for f in findings if not (f.get(column) or "").strip())
            for column in ("run_id", "scenario_id", "finding_id", "evidence_source")
            if any(not (f.get(column) or "").strip() for f in findings)
        },
        "note": (
            "Duplicate id pairs are a known defect (T124), not a data-entry error: finding_id "
            "is path plus control id, so one file breaking one control twice collides. They "
            "are reported rather than deduplicated because both rows are real findings."
        ),
    }
    (RESULTS / "data_quality.json").write_text(json.dumps(quality, indent=2), encoding="utf-8")
    (RESULTS / "duplicate_audit.json").write_text(
        json.dumps(duplicates, indent=2), encoding="utf-8"
    )

    # ---- model comparison ----------------------------------------------------------
    report = run_comparison(findings_csv, observations_csv, RESULTS)
    scores = {s["name"]: s for s in report.scores}

    rows = load_rows(findings_csv, observations_csv)
    y = labels_for(rows)
    groups = groups_for(rows)
    labels_sorted = sorted(set(y))
    plain, _ = build_matrix(rows)
    leaky, _ = build_leaky_matrix(rows)

    def evaluate(records, *, grouped: bool) -> dict:
        splitter = (
            StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
            if grouped
            else StratifiedKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
        )
        args = (records, y, groups) if grouped else (records, y)
        y_true: list[str] = []
        y_pred: list[str] = []
        for train_idx, test_idx in splitter.split(*args):
            if len({y[i] for i in train_idx}) < 2:
                continue
            logistic, _ = _fresh_models()
            pipe = make_pipeline(DictVectorizer(sparse=False), logistic)
            pipe.fit([records[i] for i in train_idx], [y[i] for i in train_idx])
            y_pred.extend(pipe.predict([records[i] for i in test_idx]))
            y_true.extend(y[i] for i in test_idx)
        if not y_true:
            return {"macro_f1": None, "accuracy": None}
        scored = _score("x", y_true, y_pred, labels_sorted)
        return {"macro_f1": scored.macro_f1, "accuracy": scored.accuracy}

    leakage = {
        "grouped_without_rule_inputs": evaluate(plain, grouped=True),
        "grouped_with_rule_inputs": evaluate(leaky, grouped=True),
        "ungrouped_without_rule_inputs": evaluate(plain, grouped=False),
        "ungrouped_with_rule_inputs": evaluate(leaky, grouped=False),
    }
    (RESULTS / "leakage_matrix.json").write_text(json.dumps(leakage, indent=2), encoding="utf-8")

    # ---- split verification ---------------------------------------------------------
    splitter = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=RANDOM_STATE)
    folds = [
        {
            "fold": i,
            "shared_templates": sorted({groups[j] for j in train} & {groups[j] for j in test}),
        }
        for i, (train, test) in enumerate(splitter.split(plain, y, groups))
    ]
    (RESULTS / "split_verification.json").write_text(
        json.dumps({"splits": 3, "folds": folds}, indent=2), encoding="utf-8"
    )

    # ---- encoder: a pickle, so it stays out of version control ----------------------
    vectoriser = DictVectorizer(sparse=False)
    vectoriser.fit(plain)
    with open(BUILD / "encoder.pkl", "wb") as fh:
        pickle.dump(vectoriser, fh)

    # Fit and persist the estimators themselves. The encoder alone was being saved, so
    # model_predictor had nothing to load and the documented train-then-predict path did not
    # exist end to end. These live in models/, which .gitignore excludes: they are large,
    # regenerable, and pickles are not something to hand round in a repository.
    from terraguard.model_trainer import labels_for

    models_dir = ROOT / "models"
    models_dir.mkdir(exist_ok=True)
    matrix = vectoriser.transform(plain)
    labels = labels_for(rows)
    logistic, forest = _fresh_models()
    logistic.fit(matrix, labels)
    forest.fit(matrix, labels)
    for name, estimator in (("logistic_regression", logistic), ("random_forest", forest)):
        with open(models_dir / f"{name}.pkl", "wb") as fh:
            pickle.dump(estimator, fh)
    print(f"  fitted models    {sorted(p.name for p in models_dir.glob('*.pkl'))}")

    _write_comparison(report, scores, leakage, RESULTS / "model_comparison.md")

    print(f"findings {len(findings)}  observations {len(observations)}")
    for name in ("logistic_regression", "random_forest"):
        if name in scores:
            print(f"  {name:22s} macro F1 {scores[name]['macro_f1']}")
    print(f"  leakage matrix        {leakage}")
    print(f"  duplicates            {len(duplicates)}")
    print(f"written to {RESULTS}")
    return 0


def _write_comparison(report, scores, leakage, path: Path) -> None:
    lines = [
        "# Severity model comparison",
        "",
        f"{report.n_findings} findings from {report.n_groups} scenario templates, grouped "
        f"cross-validation with {report.n_splits} splits.",
        "",
        "## What is being predicted",
        "",
        "The label is the severity band `severity_rules.py` assigns to a finding. The models",
        "see context only - evidence source, resource type, path shape, run-level counts - and",
        "never `control_id` or `normalised_event`, which are the two fields the rule ladder",
        "switches on.",
        "",
        "## Results",
        "",
        "| Model | Macro F1 | Weighted F1 | Accuracy | Recall on high/critical |",
        "|---|---:|---:|---:|---:|",
    ]
    for name in ("logistic_regression", "random_forest"):
        score = scores.get(name)
        if score:
            lines.append(
                f"| {name} | {score['macro_f1']} | {score['weighted_f1']} | "
                f"{score['accuracy']} | {score['high_risk_recall']} |"
            )
    lines += [
        "",
        "## The deterministic baseline is not in that table, on purpose",
        "",
        "It scores 1.0 on every metric. That is arithmetic, not evidence: the labels are the",
        "rules' own output, so the rules reproduce them exactly by construction. Listing that",
        "row beside the models would read as the baseline winning, when the comparison cannot",
        "rank them at all while the labels come from one of the contestants.",
        "",
        "Making this a real comparison needs labels from outside the rules - the independent",
        "review of a sample (T112) and the disagreement log (T113). Neither has happened, so no",
        "rules-versus-models claim belongs in the results chapter yet.",
        "",
        "## Leakage check (T076)",
        "",
        "| Split | Rule inputs withheld | Rule inputs included |",
        "|---|---:|---:|",
        f"| grouped by template | {leakage['grouped_without_rule_inputs']['macro_f1']} | "
        f"{leakage['grouped_with_rule_inputs']['macro_f1']} |",
        f"| ungrouped (random) | {leakage['ungrouped_without_rule_inputs']['macro_f1']} | "
        f"{leakage['ungrouped_with_rule_inputs']['macro_f1']} |",
        "",
        "Grouping, not the feature exclusion, is what defeats the leak: control ids are",
        "confounded with scenario templates, so a held-out template brings categories the model",
        "has never seen. The gap in the left-hand column is the price of the honest split.",
        "",
        "## Class support",
        "",
        "| Band | Findings | Independent templates |",
        "|---|---:|---:|",
    ]
    for band in report.labels:
        lines.append(
            f"| {band} | {report.class_support.get(band, 0)} | "
            f"{report.groups_per_class.get(band, 0)} |"
        )
    lines += [
        "",
        "## How much weight these numbers carry",
        "",
        "A small study: the smallest class rests on three independent templates, so differences",
        "of a few points between models are noise. The drift half of the dataset is empty, so",
        "none of this covers infrastructure drift, and the labels are one analyst's rubric",
        "applied consistently rather than reviewed ground truth.",
        "",
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


if __name__ == "__main__":
    raise SystemExit(main())
