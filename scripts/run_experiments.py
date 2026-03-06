#!/usr/bin/env python3
"""Run reproducible experiments for Shift-Left Sentinel using labeled security data."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from experiment_runner import (
    DEFAULT_CATEGORICAL_FEATURES,
    DEFAULT_NUMERIC_FEATURES,
    ExperimentConfig,
    dump_json,
    evaluate_holdout,
    evaluate_models_cv,
    load_labeled_dataset,
)
from project_config import get_experiment_defaults


def parse_args() -> argparse.Namespace:
    defaults = get_experiment_defaults()

    parser = argparse.ArgumentParser(description="Run conference-grade model experiments")
    parser.add_argument("--dataset", required=True, help="CSV with labeled security scan records")
    parser.add_argument("--output", default="artifacts/experiment_metrics.json", help="Output JSON path")
    parser.add_argument("--splits", type=int, default=int(defaults["n_splits"]))
    parser.add_argument("--repeats", type=int, default=int(defaults["n_repeats"]))
    parser.add_argument("--seed", type=int, default=int(defaults["random_seed"]))
    parser.add_argument("--estimators", type=int, default=int(defaults["n_estimators"]))
    parser.add_argument("--test-size", type=float, default=float(defaults["test_size"]))
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    config = ExperimentConfig(
        numeric_features=tuple(DEFAULT_NUMERIC_FEATURES),
        categorical_features=tuple(DEFAULT_CATEGORICAL_FEATURES),
        n_splits=args.splits,
        n_repeats=args.repeats,
        random_seed=args.seed,
        n_estimators=args.estimators,
        test_size=args.test_size,
    )

    dataset = load_labeled_dataset(args.dataset, config=config)
    cv_results = evaluate_models_cv(dataset, config)
    holdout_results = evaluate_holdout(dataset, config)

    payload = {
        "config": {
            "numeric_features": list(config.numeric_features),
            "categorical_features": list(config.categorical_features),
            "label_column": config.label_column,
            "n_splits": config.n_splits,
            "n_repeats": config.n_repeats,
            "random_seed": config.random_seed,
            "n_estimators": config.n_estimators,
            "test_size": config.test_size,
            "sample_count": int(len(dataset.labels)),
            "positive_count": int(dataset.labels.sum()),
            "negative_count": int(len(dataset.labels) - dataset.labels.sum()),
        },
        "cross_validation": cv_results,
        "holdout": holdout_results,
    }

    dump_json(payload, args.output)
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
