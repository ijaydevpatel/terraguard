"""Rank a finding by severity, and say how confident the ranking is.

The models never decide whether a finding exists or whether a control was violated. That has
already been settled deterministically by the scanners and the policy engine. All this module
does is order what was found, so an engineer reading a long report knows where to start.

Two things it refuses to do:

* predict without saying how confident it is - an unqualified label invites more trust than a
  model trained on 32 findings deserves, and
* silently disagree with the rubric. When the model and `severity_rules.py` differ, both are
  returned. A disagreement is information, not an error to be hidden.
"""

from __future__ import annotations

import pickle
from dataclasses import dataclass
from pathlib import Path

from .feature_builder import FindingRow, build_matrix
from .models import EvidenceSource, Finding, NormalisedEvent
from .severity_rules import Label, classify

__all__ = ["Prediction", "SeverityPredictor", "LOW_CONFIDENCE"]

# Below this, the ranking is not worth acting on and the report says so.
LOW_CONFIDENCE = 0.5


@dataclass(frozen=True)
class Prediction:
    finding_id: str
    rule_band: str
    rule_number: int
    rule_reason: str
    predicted_band: str | None = None
    confidence: float | None = None

    @property
    def agrees(self) -> bool:
        """True when the model reaches the same band the rubric does."""
        return self.predicted_band is not None and self.predicted_band == self.rule_band

    @property
    def is_confident(self) -> bool:
        return self.confidence is not None and self.confidence >= LOW_CONFIDENCE

    @property
    def band(self) -> str:
        """What the report should act on.

        The rubric wins. It is written down, citable and reviewable; the model is a ranking
        aid trained on a small sample. Promoting a model guess over a stated rule would make
        the tool's output impossible to defend in a review.
        """
        return self.rule_band


def _rule_label(row: FindingRow) -> Label:
    event = NormalisedEvent(row.normalised_event) if row.normalised_event else None
    return classify(
        Finding(
            finding_id=row.finding_id,
            evidence_source=EvidenceSource(row.evidence_source),
            control_id=row.control_id or None,
            normalised_event=event,
            detail=row.detail,
        )
    )


class SeverityPredictor:
    """Wraps a fitted estimator and encoder. Works with neither, which is the point.

    If no model has been trained - or the artefacts are missing on a fresh clone - the
    predictor still returns the rubric's band for every finding. The tool degrades to its
    deterministic behaviour rather than failing.
    """

    def __init__(self, model=None, encoder=None) -> None:
        self._model = model
        self._encoder = encoder

    @classmethod
    def from_artefacts(cls, model_path: str | Path, encoder_path: str | Path) -> SeverityPredictor:
        model_file, encoder_file = Path(model_path), Path(encoder_path)
        if not model_file.exists() or not encoder_file.exists():
            return cls()
        with open(model_file, "rb") as fh:
            model = pickle.load(fh)
        with open(encoder_file, "rb") as fh:
            encoder = pickle.load(fh)
        return cls(model, encoder)

    @property
    def has_model(self) -> bool:
        return self._model is not None and self._encoder is not None

    def predict(self, rows: list[FindingRow]) -> list[Prediction]:
        labels = [_rule_label(r) for r in rows]
        if not rows:
            return []
        if not self.has_model:
            return [
                Prediction(r.finding_id, lab.band, lab.rule, lab.reason)
                for r, lab in zip(rows, labels, strict=True)
            ]

        records, _ = build_matrix(rows)
        matrix = self._encoder.transform(records)
        predicted = self._model.predict(matrix)
        try:
            probabilities = self._model.predict_proba(matrix)
            classes = list(self._model.classes_)
            confidences = [float(max(p)) for p in probabilities]
            del classes
        except (AttributeError, NotImplementedError):
            confidences = [None] * len(rows)

        return [
            Prediction(
                finding_id=r.finding_id,
                rule_band=lab.band,
                rule_number=lab.rule,
                rule_reason=lab.reason,
                predicted_band=str(pred),
                confidence=conf,
            )
            for r, lab, pred, conf in zip(rows, labels, predicted, confidences, strict=True)
        ]

    @staticmethod
    def disagreements(predictions: list[Prediction]) -> list[Prediction]:
        """Every case where the model and the rubric part company.

        This list feeds the disagreement log (T113). It is the raw material for deciding
        whether a rule is wrong or the model is, and neither answer is assumed here.
        """
        return [p for p in predictions if p.predicted_band is not None and not p.agrees]
