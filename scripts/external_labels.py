"""Score the severity rules against severities nobody on this project wrote (T112, part one).

RQ2 asks whether the models rank findings better than the rules, and the labels both are
scored against come from the rules themselves. Every comparison so far was therefore circular.
This takes the one independent source available without a second person: the severity AWS
Security Hub and OpenSSF Scorecard publish for the same misconfiguration.

Each finding type is matched in datasets/external_severity_map.csv, with the documentation page
for every row. Where no published control rates a finding type, it is reported as having no
reference rather than guessed. Writes results/external_label_check.md and .json.

    python scripts/external_labels.py
"""

from __future__ import annotations

import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

BANDS = ["high_or_critical", "medium", "non_security_or_low"]
SEEDS = range(20)


def cohen_kappa(pairs: list[tuple[str, str]]) -> float | None:
    n = len(pairs)
    if not n:
        return None
    observed = sum(a == b for a, b in pairs) / n
    left, right = Counter(a for a, _ in pairs), Counter(b for _, b in pairs)
    expected = sum(left[b] * right[b] for b in BANDS) / (n * n)
    return None if expected == 1 else round((observed - expected) / (1 - expected), 4)


def score_models_against_external(rows, rule_bands, mapping, seeds=SEEDS) -> dict:
    """Out-of-fold model predictions, scored against the published band instead of the rules.

    The models were trained on rule labels, so this asks a narrower question than RQ2 in full:
    on the findings an outside source rates, does either model land nearer that rating than
    the rules it learned from? Grouped folds as everywhere else, 20 split seeds.
    """
    import statistics

    from sklearn.feature_extraction import DictVectorizer
    from sklearn.model_selection import StratifiedGroupKFold
    from sklearn.pipeline import make_pipeline

    from terraguard.feature_builder import build_matrix, groups_for
    from terraguard.model_trainer import MIN_GROUPS, _fresh_models

    records, _ = build_matrix(rows)
    groups = groups_for(rows)
    external = []
    for row in rows:
        key = (row.control_id or "-", row.normalised_event, row.resource_type)
        ref = mapping.get(key) or mapping.get((key[0], key[1], "*"))
        external.append(ref["external_band"] or None)
    referenced = [i for i, band in enumerate(external) if band]

    rates: dict[str, list[float]] = {"logistic_regression": [], "random_forest": []}
    for seed in seeds:
        splitter = StratifiedGroupKFold(n_splits=MIN_GROUPS, shuffle=True, random_state=seed)
        for name, model in zip(rates, _fresh_models(), strict=True):
            predicted: dict[int, str] = {}
            for train, test in splitter.split(records, rule_bands, groups):
                pipe = make_pipeline(DictVectorizer(sparse=False), model)
                pipe.fit([records[i] for i in train], [rule_bands[i] for i in train])
                for i, p in zip(test, pipe.predict([records[i] for i in test]), strict=True):
                    predicted[i] = p
            hits = sum(predicted[i] == external[i] for i in referenced)
            rates[name].append(hits / len(referenced))
    return {
        name: {
            "mean_agreement": round(statistics.mean(v), 4),
            "min": round(min(v), 4),
            "max": round(max(v), 4),
        }
        for name, v in rates.items()
    }


def main() -> int:
    from terraguard.feature_builder import load_rows
    from terraguard.model_trainer import labels_for

    mapping = {}
    with open(ROOT / "datasets" / "external_severity_map.csv", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            mapping[(row["control_id"], row["normalised_event"], row["resource_type"])] = row

    rows = load_rows(ROOT / "datasets/findings.csv", ROOT / "datasets/observations.csv")
    rule_bands = labels_for(rows)

    pairs: list[tuple[str, str]] = []
    per_type: dict[tuple, Counter] = defaultdict(Counter)
    unreferenced = Counter()
    for row, band in zip(rows, rule_bands, strict=True):
        key = (row.control_id or "-", row.normalised_event, row.resource_type)
        ref = mapping.get(key) or mapping.get((key[0], key[1], "*"))
        if ref is None:
            raise SystemExit(f"finding type not in the map: {key}")
        if not ref["external_band"]:
            unreferenced[key] += 1
            continue
        pairs.append((band, ref["external_band"]))
        per_type[(key, ref["external_control"], ref["external_band"], ref["match"])][band] += 1

    agree = sum(a == b for a, b in pairs)
    models = score_models_against_external(rows, rule_bands, mapping)
    summary = {
        "models_vs_external_20_seeds": models,
        "findings": len(rows),
        "with_external_reference": len(pairs),
        "without_external_reference": sum(unreferenced.values()),
        "agreement": agree,
        "agreement_rate": round(agree / len(pairs), 4) if pairs else None,
        "cohen_kappa": cohen_kappa(pairs),
        "confusion_rule_vs_external": {
            r: {e: sum(1 for a, b in pairs if a == r and b == e) for e in BANDS} for r in BANDS
        },
    }
    (ROOT / "results" / "external_label_check.json").write_text(
        json.dumps(summary, indent=2), encoding="utf-8"
    )

    lines = [
        "# Rules against published severities (T112, part one)",
        "",
        f"{summary['with_external_reference']} of {summary['findings']} findings have a matching "
        "published control. On those, the rules agree with the published severity on "
        f"{agree} ({summary['agreement_rate']:.1%}), Cohen's kappa {summary['cohen_kappa']}.",
        "",
        "| Finding type | Control | External | Published band | Rule band | Findings | Agrees |",
        "|---|---|---|---|---|---:|---|",
    ]
    for (key, ext, ext_band, match), bands in sorted(per_type.items()):
        for band, count in bands.items():
            label = f"{key[0]} {key[2]}" + (" (partial match)" if match == "partial" else "")
            lines.append(
                f"| {label} | {key[0]} | {ext} | {ext_band} | {band} | {count} | "
                f"{'yes' if band == ext_band else '**no**'} |"
            )
    lines += [
        "",
        "## Models against the same published severities",
        "",
        "Out-of-fold predictions under grouped cross-validation, 20 split seeds. The models were",
        "trained on rule labels, so this asks only whether either lands nearer the published",
        "rating than the rules it learned from.",
        "",
        "| Predictor | Agreement with published band |",
        "|---|---|",
        f"| Rules | {summary['agreement_rate']:.1%} |",
    ]
    for name, m in models.items():
        lines.append(
            f"| {name} | {m['mean_agreement']:.1%} (range {m['min']:.1%} to {m['max']:.1%}) |"
        )
    lines += [
        "",
        f"{summary['without_external_reference']} findings have no published equivalent:",
        "",
    ]
    for key, count in unreferenced.most_common():
        lines.append(f"- {key[0]} {key[1]} on {key[2]}: {count}")
    lines += [
        "",
        "Sources and the reasoning for every match are in `datasets/external_severity_map.csv`.",
        "Critical and High map to high_or_critical, Medium to medium, Low to non_security_or_low.",
        "",
    ]
    (ROOT / "results" / "external_label_check.md").write_text("\n".join(lines), encoding="utf-8")
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
