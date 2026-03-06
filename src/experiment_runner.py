"""Experiment pipeline utilities for conference-grade evaluation."""

from __future__ import annotations

import csv
import json
from dataclasses import dataclass
from pathlib import Path
from statistics import mean, pstdev
from typing import Any, Dict, List, Sequence

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction import DictVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    f1_score,
    matthews_corrcoef,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import RepeatedStratifiedKFold, StratifiedShuffleSplit
from sklearn.pipeline import Pipeline

LABEL_COLUMN = "final_label"
DEFAULT_NUMERIC_FEATURES = ["lines_of_code", "cyclomatic_comp"]
DEFAULT_CATEGORICAL_FEATURES = ["vulnerability_type", "sast_alert_status", "scan_accuracy"]


@dataclass(frozen=True)
class ExperimentConfig:
    """Configuration for reproducible model evaluation."""

    numeric_features: Sequence[str] = tuple(DEFAULT_NUMERIC_FEATURES)
    categorical_features: Sequence[str] = tuple(DEFAULT_CATEGORICAL_FEATURES)
    label_column: str = LABEL_COLUMN
    n_splits: int = 5
    n_repeats: int = 3
    random_seed: int = 42
    n_estimators: int = 200
    test_size: float = 0.2


@dataclass(frozen=True)
class DatasetBundle:
    """Typed container for dataset records and labels."""

    records: List[Dict[str, Any]]
    labels: np.ndarray


def _label_to_binary(value: str) -> int:
    normalized = str(value).strip().lower()
    if normalized in {"risky", "1", "true", "positive", "high"}:
        return 1
    if normalized in {"non-risky", "non_risky", "0", "false", "negative", "low"}:
        return 0
    raise ValueError(f"Unsupported label value '{value}'")


def load_labeled_dataset(csv_path: str | Path, config: ExperimentConfig) -> DatasetBundle:
    """Load experiment dataset from CSV and return records + binary labels."""
    path = Path(csv_path)
    if not path.exists():
        raise FileNotFoundError(f"Dataset not found: {path}")

    required = list(config.numeric_features) + list(config.categorical_features) + [config.label_column]
    rows: List[Dict[str, Any]] = []
    labels: List[int] = []

    with path.open("r", newline="", encoding="utf-8") as csv_file:
        reader = csv.DictReader(csv_file)
        missing = [col for col in required if col not in (reader.fieldnames or [])]
        if missing:
            raise ValueError(f"Dataset is missing required columns: {missing}")

        for row in reader:
            sample: Dict[str, Any] = {}
            for col in config.numeric_features:
                sample[col] = float(row[col])
            for col in config.categorical_features:
                sample[col] = row[col]

            rows.append(sample)
            labels.append(_label_to_binary(row[config.label_column]))

    if not rows:
        raise ValueError("Dataset is empty.")

    return DatasetBundle(records=rows, labels=np.array(labels, dtype=int))


def _build_models(config: ExperimentConfig) -> Dict[str, Any]:
    models: Dict[str, Any] = {
        "logistic_regression": LogisticRegression(max_iter=1500, random_state=config.random_seed),
        "random_forest": RandomForestClassifier(
            n_estimators=config.n_estimators,
            random_state=config.random_seed,
            class_weight="balanced",
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(random_state=config.random_seed),
    }

    try:
        from xgboost import XGBClassifier  # type: ignore

        models["xgboost"] = XGBClassifier(
            n_estimators=300,
            random_state=config.random_seed,
            max_depth=5,
            learning_rate=0.05,
            subsample=0.9,
            colsample_bytree=0.9,
            eval_metric="logloss",
        )
    except Exception:
        pass

    return models


def _build_pipeline(estimator: Any) -> Pipeline:
    return Pipeline(
        steps=[
            ("vectorizer", DictVectorizer(sparse=False)),
            ("clf", estimator),
        ]
    )


def _collect_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "f1": float(f1_score(y_true, y_pred, zero_division=0)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
    }


def evaluate_models_cv(dataset: DatasetBundle, config: ExperimentConfig) -> Dict[str, Dict[str, float | int]]:
    """Run repeated stratified CV for all baseline models."""
    splitter = RepeatedStratifiedKFold(
        n_splits=config.n_splits,
        n_repeats=config.n_repeats,
        random_state=config.random_seed,
    )

    x_index = np.arange(len(dataset.records))
    output: Dict[str, Dict[str, float | int]] = {}

    for model_name, estimator in _build_models(config).items():
        fold_metrics: List[Dict[str, float]] = []
        for train_idx, test_idx in splitter.split(x_index, dataset.labels):
            x_train = [dataset.records[i] for i in train_idx]
            x_test = [dataset.records[i] for i in test_idx]
            y_train = dataset.labels[train_idx]
            y_test = dataset.labels[test_idx]

            pipeline = _build_pipeline(estimator)
            pipeline.fit(x_train, y_train)
            y_pred = pipeline.predict(x_test)

            clf = pipeline.named_steps["clf"]
            if hasattr(clf, "predict_proba"):
                y_prob = pipeline.predict_proba(x_test)[:, 1]
            else:
                decision = pipeline.decision_function(x_test)
                y_prob = 1 / (1 + np.exp(-decision))

            fold_metrics.append(_collect_metrics(y_test, y_pred, y_prob))

        model_result: Dict[str, float | int] = {
            "fold_count": len(fold_metrics),
            "seed": config.random_seed,
        }
        for metric_name in fold_metrics[0]:
            values = [m[metric_name] for m in fold_metrics]
            model_result[f"{metric_name}_mean"] = mean(values)
            model_result[f"{metric_name}_std"] = pstdev(values)
        output[model_name] = model_result

    return output


def evaluate_holdout(dataset: DatasetBundle, config: ExperimentConfig) -> Dict[str, Dict[str, float]]:
    """Evaluate all models on a stratified holdout split for deployment realism."""
    splitter = StratifiedShuffleSplit(
        n_splits=1,
        test_size=config.test_size,
        random_state=config.random_seed,
    )

    x_index = np.arange(len(dataset.records))
    (train_idx, test_idx), = splitter.split(x_index, dataset.labels)
    x_train = [dataset.records[i] for i in train_idx]
    x_test = [dataset.records[i] for i in test_idx]
    y_train = dataset.labels[train_idx]
    y_test = dataset.labels[test_idx]

    results: Dict[str, Dict[str, float]] = {}
    for model_name, estimator in _build_models(config).items():
        pipeline = _build_pipeline(estimator)
        pipeline.fit(x_train, y_train)
        y_pred = pipeline.predict(x_test)

        clf = pipeline.named_steps["clf"]
        if hasattr(clf, "predict_proba"):
            y_prob = pipeline.predict_proba(x_test)[:, 1]
        else:
            decision = pipeline.decision_function(x_test)
            y_prob = 1 / (1 + np.exp(-decision))

        results[model_name] = _collect_metrics(y_test, y_pred, y_prob)

    return results


def dump_json(data: Dict[str, object], output_path: str | Path) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as fp:
        json.dump(data, fp, indent=2, sort_keys=True)
