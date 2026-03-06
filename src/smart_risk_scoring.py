"""Smart risk scoring module powered by scikit-learn.

This module introduces an ML-driven risk classifier for Shift-Left Sentinel.
It predicts commit risk from:
- code_churn
- file_entropy
- author_risk_score

The model is persisted to disk and can be retrained from local feedback data.
"""

from __future__ import annotations

import csv
import os
import pickle
from dataclasses import dataclass
from typing import Dict, Iterable, List

from sklearn.ensemble import RandomForestClassifier

FEATURE_COLUMNS = ["code_churn", "file_entropy", "author_risk_score"]
LABEL_COLUMN = "risk_label"


@dataclass(frozen=True)
class CommitFeatures:
    """Strongly-typed commit feature input."""

    code_churn: int
    file_entropy: float
    author_risk_score: float

    def as_dict(self) -> Dict[str, float]:
        return {
            "code_churn": int(self.code_churn),
            "file_entropy": float(self.file_entropy),
            "author_risk_score": float(self.author_risk_score),
        }


class SmartRiskScorer:
    """RandomForest-based risk model with local persistence."""

    def __init__(self, model_path: str = "smart_risk_model.pkl") -> None:
        self.model_path = model_path
        self.model = self._load_or_create_model()

    def _load_or_create_model(self) -> RandomForestClassifier:
        if os.path.exists(self.model_path):
            with open(self.model_path, "rb") as model_file:
                return pickle.load(model_file)

        model = RandomForestClassifier(
            n_estimators=200,
            random_state=42,
            class_weight="balanced",
        )
        self._bootstrap_train(model)
        self.save_model(model)
        return model

    def _bootstrap_train(self, model: RandomForestClassifier) -> None:
        """Train an initial model so predictions work on first run."""
        baseline_rows = [
            # Low-risk examples
            {"code_churn": 12, "file_entropy": 3.2, "author_risk_score": 0.08, "risk_label": 0},
            {"code_churn": 30, "file_entropy": 3.6, "author_risk_score": 0.12, "risk_label": 0},
            {"code_churn": 45, "file_entropy": 3.7, "author_risk_score": 0.15, "risk_label": 0},
            # High-risk examples
            {"code_churn": 180, "file_entropy": 5.1, "author_risk_score": 0.44, "risk_label": 1},
            {"code_churn": 260, "file_entropy": 5.8, "author_risk_score": 0.63, "risk_label": 1},
            {"code_churn": 350, "file_entropy": 6.2, "author_risk_score": 0.72, "risk_label": 1},
            # Mixed boundary examples
            {"code_churn": 80, "file_entropy": 4.1, "author_risk_score": 0.27, "risk_label": 0},
            {"code_churn": 120, "file_entropy": 4.8, "author_risk_score": 0.33, "risk_label": 1},
        ]
        x_rows = [[row[c] for c in FEATURE_COLUMNS] for row in baseline_rows]
        y_rows = [row[LABEL_COLUMN] for row in baseline_rows]
        model.fit(x_rows, y_rows)

    def save_model(self, model: RandomForestClassifier | None = None) -> None:
        with open(self.model_path, "wb") as model_file:
            pickle.dump(model or self.model, model_file)

    def predict_risk(self, commit_data: Dict[str, float] | CommitFeatures) -> Dict[str, float | str]:
        """Predict commit risk and return label + confidence scores.

        Returns:
            {
              "risk_label": "high" | "low",
              "confidence_score": float,   # 0.0..1.0 (confidence in predicted label)
              "risk_probability": float    # 0.0..1.0 probability of high-risk class
            }
        """
        normalized = self._normalize_commit_data(commit_data)
        feature_vector = [[normalized[col] for col in FEATURE_COLUMNS]]

        probabilities = self.model.predict_proba(feature_vector)[0]
        low_prob, high_prob = float(probabilities[0]), float(probabilities[1])
        predicted_high_risk = high_prob >= 0.5

        return {
            "risk_label": "high" if predicted_high_risk else "low",
            "confidence_score": max(low_prob, high_prob),
            "risk_probability": high_prob,
        }

    @staticmethod
    def _normalize_commit_data(commit_data: Dict[str, float] | CommitFeatures) -> Dict[str, float]:
        raw = commit_data.as_dict() if isinstance(commit_data, CommitFeatures) else commit_data

        missing = [col for col in FEATURE_COLUMNS if col not in raw]
        if missing:
            raise ValueError(f"Missing required features: {missing}")

        return {
            "code_churn": int(raw["code_churn"]),
            "file_entropy": float(raw["file_entropy"]),
            "author_risk_score": float(raw["author_risk_score"]),
        }


class FeedbackLoop:
    """Collects human feedback and updates the model from local registry data."""

    def __init__(
        self,
        scorer: SmartRiskScorer,
        registry_path: str = "feedback_registry.csv",
    ) -> None:
        self.scorer = scorer
        self.registry_path = registry_path
        self._ensure_registry_exists()

    def retrain_model(self, commit_data: Dict[str, float] | CommitFeatures, was_false_positive: bool) -> None:
        """Append feedback to local registry and retrain the model.

        If a flagged commit was a false positive, it is recorded as a low-risk (0)
        example so the model learns to avoid future false alarms on similar patterns.
        """
        normalized = self.scorer._normalize_commit_data(commit_data)
        feedback_label = 0 if was_false_positive else 1
        row = {**normalized, LABEL_COLUMN: feedback_label}

        self._append_registry_row(row)
        all_rows = list(self._iter_registry_rows())

        if not all_rows:
            return

        x_rows = [[r[c] for c in FEATURE_COLUMNS] for r in all_rows]
        y_rows = [r[LABEL_COLUMN] for r in all_rows]

        self.scorer.model.fit(x_rows, y_rows)
        self.scorer.save_model()

    def _ensure_registry_exists(self) -> None:
        if os.path.exists(self.registry_path):
            return

        with open(self.registry_path, "w", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=FEATURE_COLUMNS + [LABEL_COLUMN])
            writer.writeheader()

    def _append_registry_row(self, row: Dict[str, float | int]) -> None:
        with open(self.registry_path, "a", newline="", encoding="utf-8") as csv_file:
            writer = csv.DictWriter(csv_file, fieldnames=FEATURE_COLUMNS + [LABEL_COLUMN])
            writer.writerow(row)

    def _iter_registry_rows(self) -> Iterable[Dict[str, float | int]]:
        with open(self.registry_path, "r", newline="", encoding="utf-8") as csv_file:
            reader = csv.DictReader(csv_file)
            for row in reader:
                yield {
                    "code_churn": int(row["code_churn"]),
                    "file_entropy": float(row["file_entropy"]),
                    "author_risk_score": float(row["author_risk_score"]),
                    "risk_label": int(row["risk_label"]),
                }
