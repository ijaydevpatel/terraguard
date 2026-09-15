"""Train and score the severity models against the deterministic baseline.

Three things are being compared, on identical folds:

* `severity_rules.py` - the frozen lookup table, the non-AI comparator
* Logistic Regression - interpretable, coefficients reportable
* Random Forest - non-linear, feature importances reportable

Folds come from `StratifiedGroupKFold` grouped by scenario template, so no template ever
appears in both train and test. With this few independent groups that is a hard constraint,
not a refinement: without it the models would be scored on near-copies of their own training
data and every number here would be too high.

The dataset is small. Nothing in this module tries to hide that - fold counts, per-class
support and the number of independent groups are reported alongside every score so a reader
can judge how much weight the figures carry.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .feature_builder import (
    FindingRow,
    build_leaky_matrix,
    build_matrix,
    groups_for,
    load_rows,
)
from .models import EvidenceSource, Finding, NormalisedEvent
from .severity_rules import classify

__all__ = ["TrainingReport", "label_for", "labels_for", "run_comparison", "MIN_GROUPS"]

MIN_GROUPS = 3
RANDOM_STATE = 20260916


@dataclass
class ModelScore:
    name: str
    macro_f1: float = 0.0
    weighted_f1: float = 0.0
    accuracy: float = 0.0
    per_class: dict = field(default_factory=dict)
    confusion: list = field(default_factory=list)
    high_risk_recall: float = 0.0
    note: str = ""


@dataclass
class TrainingReport:
    n_findings: int = 0
    n_groups: int = 0
    n_splits: int = 0
    class_support: dict = field(default_factory=dict)
    groups_per_class: dict = field(default_factory=dict)
    labels: list = field(default_factory=list)
    scores: list = field(default_factory=list)
    leakage: dict = field(default_factory=dict)
    coefficients: dict = field(default_factory=dict)
    importances: dict = field(default_factory=dict)
    warnings: list = field(default_factory=list)


def label_for(row: FindingRow) -> str:
    """The deterministic band for one finding. This is the training label."""
    event = NormalisedEvent(row.normalised_event) if row.normalised_event else None
    finding = Finding(
        finding_id=row.finding_id,
        evidence_source=EvidenceSource(row.evidence_source),
        control_id=row.control_id or None,
        normalised_event=event,
        detail=row.detail,
    )
    return classify(finding).band


def labels_for(rows: list[FindingRow]) -> list[str]:
    return [label_for(r) for r in rows]


def _baseline_predictions(rows: list[FindingRow]) -> list[str]:
    """The comparator predicts by applying the rules - it has no training step.

    It therefore scores the same on every fold. Reporting it as a cross-validated number
    would imply a variance it does not have, so it is scored once over all rows and
    labelled as such.
    """
    return labels_for(rows)


def _score(name: str, y_true, y_pred, labels, note: str = "") -> ModelScore:
    from sklearn.metrics import (
        accuracy_score,
        confusion_matrix,
        f1_score,
        precision_recall_fscore_support,
    )

    precision, recall, f1, support = precision_recall_fscore_support(
        y_true, y_pred, labels=labels, zero_division=0
    )
    per_class = {
        band: {
            "precision": round(float(precision[i]), 4),
            "recall": round(float(recall[i]), 4),
            "f1": round(float(f1[i]), 4),
            "support": int(support[i]),
        }
        for i, band in enumerate(labels)
    }
    high = "high_or_critical"
    return ModelScore(
        name=name,
        macro_f1=round(float(f1_score(y_true, y_pred, average="macro", zero_division=0)), 4),
        weighted_f1=round(float(f1_score(y_true, y_pred, average="weighted", zero_division=0)), 4),
        accuracy=round(float(accuracy_score(y_true, y_pred)), 4),
        per_class=per_class,
        confusion=confusion_matrix(y_true, y_pred, labels=labels).tolist(),
        high_risk_recall=per_class.get(high, {}).get("recall", 0.0),
        note=note,
    )


def _cross_val_predict(estimator, records, y, groups, n_splits):
    """Manual grouped CV. Returns (y_true_ordered, y_pred_ordered, folds_used).

    sklearn's cross_val_predict would do this, but with folds this small a fold can end up
    missing a class entirely. Doing the loop by hand means such a fold can be skipped and
    counted rather than silently producing a misleading score.
    """
    from sklearn.feature_extraction import DictVectorizer
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.pipeline import make_pipeline

    splitter = StratifiedGroupKFold(n_splits=n_splits, shuffle=True, random_state=RANDOM_STATE)
    y_true: list[str] = []
    y_pred: list[str] = []
    folds_used = 0
    for train_idx, test_idx in splitter.split(records, y, groups):
        train_y = [y[i] for i in train_idx]
        if len(set(train_y)) < 2:
            continue
        pipeline = make_pipeline(DictVectorizer(sparse=False), estimator)
        pipeline.fit([records[i] for i in train_idx], train_y)
        predicted = pipeline.predict([records[i] for i in test_idx])
        y_true.extend(y[i] for i in test_idx)
        y_pred.extend(predicted)
        folds_used += 1
    return y_true, y_pred, folds_used


def _fresh_models():
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression

    logistic = LogisticRegression(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE)
    forest = RandomForestClassifier(
        n_estimators=300,
        class_weight="balanced_subsample",
        random_state=RANDOM_STATE,
        min_samples_leaf=1,
    )
    return logistic, forest


def run_comparison(
    findings_csv: str | Path,
    observations_csv: str | Path,
    out_dir: str | Path,
) -> TrainingReport:
    """Score baseline, LR and RF on identical grouped folds. Writes artefacts to out_dir."""
    from collections import Counter

    from sklearn.feature_extraction import DictVectorizer

    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)

    rows = load_rows(findings_csv, observations_csv)
    y = labels_for(rows)
    groups = groups_for(rows)
    records, _ = build_matrix(rows)

    labels_sorted = sorted(set(y))
    groups_per_class = {
        band: len({g for g, lab in zip(groups, y, strict=True) if lab == band})
        for band in labels_sorted
    }
    report = TrainingReport(
        n_findings=len(rows),
        n_groups=len(set(groups)),
        class_support=dict(Counter(y)),
        groups_per_class=groups_per_class,
        labels=labels_sorted,
    )

    # model_features.csv - the matrix actually trained on, committed for the write-up.
    vectoriser = DictVectorizer(sparse=False)
    matrix = vectoriser.fit_transform(records)
    names = vectoriser.get_feature_names_out()
    with open(out / "model_features.csv", "w", encoding="utf-8", newline="") as fh:
        import csv as _csv

        writer = _csv.writer(fh)
        writer.writerow(["finding_id", "scenario_id", "label", *names])
        for row, vec, lab in zip(rows, matrix, y, strict=True):
            writer.writerow(
                [row.finding_id, row.scenario_id, lab, *[round(float(v), 6) for v in vec]]
            )

    smallest = min(groups_per_class.values()) if groups_per_class else 0
    if smallest < MIN_GROUPS:
        report.warnings.append(
            f"smallest class has {smallest} independent template(s); "
            f"grouped cross-validation needs at least {MIN_GROUPS}"
        )
    n_splits = max(2, min(MIN_GROUPS, smallest)) if smallest >= 2 else 0
    report.n_splits = n_splits

    baseline = _score(
        "deterministic_rules",
        y,
        _baseline_predictions(rows),
        labels_sorted,
        note=(
            "DEFINITIONAL, not a result. The labels are this function's own output, so a "
            "score of 1.0 is arithmetic rather than evidence. It is listed to make the "
            "circularity visible, and must not be read as the baseline beating the models."
        ),
    )
    report.scores.append(asdict(baseline))

    if n_splits < 2:
        report.warnings.append("too few groups to cross-validate; models not trained")
        (out / "training_report.json").write_text(
            json.dumps(asdict(report), indent=2), encoding="utf-8"
        )
        return report

    logistic, forest = _fresh_models()
    for name, estimator in (("logistic_regression", logistic), ("random_forest", forest)):
        y_true, y_pred, folds = _cross_val_predict(estimator, records, y, groups, n_splits)
        if not y_true:
            report.warnings.append(f"{name}: every fold was degenerate; no score produced")
            continue
        note = f"{folds}/{n_splits} folds usable, grouped by scenario template"
        report.scores.append(asdict(_score(name, y_true, y_pred, labels_sorted, note)))

    # Coefficients and importances, fitted on everything - for interpretation only, never
    # quoted as performance.
    logistic, forest = _fresh_models()
    logistic.fit(matrix, y)
    forest.fit(matrix, y)
    report.coefficients = {
        band: {
            str(n): round(float(c), 4)
            for n, c in sorted(
                zip(names, logistic.coef_[i], strict=True),
                key=lambda kv: abs(kv[1]),
                reverse=True,
            )[:10]
        }
        for i, band in enumerate(logistic.classes_)
    }
    report.importances = {
        str(n): round(float(v), 4)
        for n, v in sorted(
            zip(names, forest.feature_importances_, strict=True),
            key=lambda kv: kv[1],
            reverse=True,
        )[:15]
    }

    # T076 leakage check: hand the models the two fields the rules switch on.
    leaky_records, _ = build_leaky_matrix(rows)
    logistic, _ = _fresh_models()
    ly_true, ly_pred, lfolds = _cross_val_predict(logistic, leaky_records, y, groups, n_splits)
    if ly_true:
        leaked = _score("logistic_regression_with_rule_inputs", ly_true, ly_pred, labels_sorted)
        report.leakage = {
            "macro_f1": leaked.macro_f1,
            "accuracy": leaked.accuracy,
            "folds_used": lfolds,
            "interpretation": (
                "Measured under the same grouped folds. Compare against the ungrouped "
                "figure: if grouping alone suppresses the leak, that is because control ids "
                "are template-specific, so a held-out template contributes categories the "
                "model never saw in training."
            ),
        }

    (out / "training_report.json").write_text(
        json.dumps(asdict(report), indent=2), encoding="utf-8"
    )
    return report


# The comparison report itself is written by scripts/build_results.py, which owns the
# framing: the baseline is excluded from the headline table with its reason stated, and the
# four-way leakage matrix is attached. Keeping report generation here as well produced two
# comparison files saying different things, which is how a reader ends up quoting the wrong
# one.
