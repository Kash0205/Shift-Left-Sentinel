"""Centralized project configuration loader."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict


DEFAULT_CONFIG: Dict[str, Any] = {
    "risk": {"threshold": 80},
    "experiments": {
        "n_splits": 5,
        "n_repeats": 3,
        "random_seed": 42,
        "n_estimators": 200,
        "test_size": 0.2,
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    output = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(output.get(key), dict):
            output[key] = _deep_merge(output[key], value)
        else:
            output[key] = value
    return output


def load_project_config(config_path: str | Path | None = None) -> Dict[str, Any]:
    """Load config JSON and merge with defaults."""
    root = Path(__file__).resolve().parents[1]
    path = Path(config_path) if config_path else root / "config" / "project_config.json"

    if not path.exists():
        return dict(DEFAULT_CONFIG)

    with path.open("r", encoding="utf-8") as fp:
        user_config = json.load(fp)

    return _deep_merge(DEFAULT_CONFIG, user_config)


def get_risk_threshold(config_path: str | Path | None = None) -> int:
    cfg = load_project_config(config_path)
    return int(cfg["risk"]["threshold"])


def get_experiment_defaults(config_path: str | Path | None = None) -> Dict[str, Any]:
    cfg = load_project_config(config_path)
    return dict(cfg["experiments"])
