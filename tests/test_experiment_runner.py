import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from experiment_runner import ExperimentConfig, evaluate_holdout, evaluate_models_cv, load_labeled_dataset


CSV_TEXT = """commit_id,lines_of_code,cyclomatic_comp,vulnerability_type,sast_alert_status,scan_accuracy,final_label
c1,120,10,SQL Injection,Flagged,True Positive,Risky
c2,85,7,None,Clean,True Negative,Non-Risky
c3,260,19,Reentrancy Flaw,Flagged,True Positive,Risky
c4,45,4,None,Flagged,False Positive,Non-Risky
c5,710,22,Directory Traversal,Clean,False Negative,Risky
c6,98,5,None,Clean,True Negative,Non-Risky
c7,340,14,Cross-Site Scripting,Flagged,True Positive,Risky
c8,66,6,None,Clean,True Negative,Non-Risky
c9,520,31,Buffer Overflow,Flagged,True Positive,Risky
c10,54,3,None,Clean,True Negative,Non-Risky
c11,280,15,Malicious URL,Flagged,True Positive,Risky
c12,77,5,None,Clean,True Negative,Non-Risky
"""


def test_load_dataset_with_categorical_schema(tmp_path: Path) -> None:
    dataset_file = tmp_path / "labeled.csv"
    dataset_file.write_text(CSV_TEXT, encoding="utf-8")

    cfg = ExperimentConfig(n_splits=2, n_repeats=1)
    ds = load_labeled_dataset(dataset_file, config=cfg)

    assert len(ds.records) == 12
    assert ds.labels.shape[0] == 12
    assert set(ds.labels.tolist()) == {0, 1}


def test_evaluate_models_and_holdout(tmp_path: Path) -> None:
    dataset_file = tmp_path / "labeled.csv"
    dataset_file.write_text(CSV_TEXT, encoding="utf-8")

    cfg = ExperimentConfig(n_splits=2, n_repeats=1, random_seed=11, n_estimators=20, test_size=0.25)
    ds = load_labeled_dataset(dataset_file, config=cfg)

    cv_results = evaluate_models_cv(ds, cfg)
    holdout = evaluate_holdout(ds, cfg)

    assert "random_forest" in cv_results
    assert "logistic_regression" in cv_results
    assert "hist_gradient_boosting" in cv_results
    assert cv_results["random_forest"]["fold_count"] == 2
    assert 0 <= cv_results["random_forest"]["f1_mean"] <= 1

    assert "random_forest" in holdout
    assert 0 <= holdout["random_forest"]["roc_auc"] <= 1
