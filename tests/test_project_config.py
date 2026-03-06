import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from project_config import get_experiment_defaults, get_risk_threshold, load_project_config


def test_load_project_config_defaults_when_missing(tmp_path: Path) -> None:
    cfg = load_project_config(tmp_path / "missing.json")
    assert cfg["risk"]["threshold"] == 80
    assert cfg["experiments"]["n_splits"] == 5


def test_load_project_config_merges_overrides(tmp_path: Path) -> None:
    cfg_file = tmp_path / "cfg.json"
    cfg_file.write_text(
        json.dumps({"risk": {"threshold": 65}, "experiments": {"n_splits": 7}}),
        encoding="utf-8",
    )

    assert get_risk_threshold(cfg_file) == 65
    exp = get_experiment_defaults(cfg_file)
    assert exp["n_splits"] == 7
    assert exp["n_estimators"] == 200
