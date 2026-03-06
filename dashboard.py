"""Streamlit dashboard for Shift-Left Sentinel conference demos."""

from __future__ import annotations

import os
import random
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import streamlit as st

# Make local src/ importable when running from repository root.
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

try:
    from smart_risk_scoring import CommitFeatures, FeedbackLoop, SmartRiskScorer
except Exception:  # Keep dashboard usable even if backend import fails.
    CommitFeatures = None
    FeedbackLoop = None
    SmartRiskScorer = None


@st.cache_data(show_spinner=False)
def generate_mock_data(seed: int = 42) -> dict[str, Any]:
    """Generate realistic mock data so the dashboard is populated immediately."""
    rng = np.random.default_rng(seed)
    random.seed(seed)

    # 1) Security debt trend (downward over time)
    weeks = pd.date_range(end=datetime.today(), periods=12, freq="W")
    downward_curve = np.linspace(8.3, 2.1, len(weeks))
    noise = rng.normal(0, 0.35, len(weeks))
    avg_risk = np.clip(downward_curve + noise, 1.0, 10.0)
    debt_trend = pd.DataFrame(
        {
            "Week": weeks,
            "Average Risk Score": np.round(avg_risk, 2),
        }
    )

    # 2) False positive breakdown
    total_false_positives = int(rng.integers(90, 180))
    auto_resolved = int(total_false_positives * rng.uniform(0.62, 0.82))
    human_intervention = total_false_positives - auto_resolved
    false_positive_split = pd.DataFrame(
        {
            "Resolution": ["Auto-Resolved (ML)", "Human Intervention"],
            "Count": [auto_resolved, human_intervention],
        }
    )

    # 3) RWCS heatmap/table (file x week cumulative risk)
    files = [
        "src/auth.py",
        "src/api_gateway.py",
        "src/permissions.py",
        "src/upload_handler.py",
        "src/db_connector.py",
        "src/token_manager.py",
        "src/config_loader.py",
        "src/payment_adapter.py",
    ]
    week_labels = [f"W{i + 1}" for i in range(8)]
    rwcs_matrix = rng.integers(8, 95, size=(len(files), len(week_labels)))
    rwcs_df = pd.DataFrame(rwcs_matrix, index=files, columns=week_labels)
    rwcs_df["Cumulative RWCS"] = rwcs_df.sum(axis=1)
    rwcs_df = rwcs_df.sort_values("Cumulative RWCS", ascending=False)

    # Review flags with associated feature vectors
    flagged_commits = []
    base_date = datetime.today() - timedelta(days=16)
    authors = ["alice", "bob", "charlie", "dana", "erin"]
    for i in range(8):
        flagged_commits.append(
            {
                "commit_id": f"cmt-{1000 + i}",
                "author": random.choice(authors),
                "file": random.choice(files),
                "timestamp": (base_date + timedelta(days=i * 2)).strftime("%Y-%m-%d"),
                "risk_score": round(float(rng.uniform(5.2, 9.7)), 2),
                "code_churn": int(rng.integers(60, 380)),
                "file_entropy": round(float(rng.uniform(3.5, 6.5)), 2),
                "author_risk_score": round(float(rng.uniform(0.1, 0.85)), 2),
            }
        )

    return {
        "debt_trend": debt_trend,
        "false_positive_split": false_positive_split,
        "rwcs_df": rwcs_df,
        "flagged_commits": flagged_commits,
    }


def ensure_model_ready(model_path: str = "smart_risk_model.pkl") -> tuple[Any, Any, str]:
    """Ensure there is a model for demo interaction and provide status."""
    if SmartRiskScorer is None or FeedbackLoop is None:
        return None, None, "Backend model module unavailable; using mock retraining."

    if not os.path.exists(model_path):
        scorer = SmartRiskScorer(model_path=model_path)
        feedback_loop = FeedbackLoop(scorer=scorer)
        return scorer, feedback_loop, "Model file missing. Trained a fresh model on baseline data."

    scorer = SmartRiskScorer(model_path=model_path)
    feedback_loop = FeedbackLoop(scorer=scorer)
    return scorer, feedback_loop, "Loaded existing model from disk."


def retrain_model(feedback_loop: Any, commit: dict[str, Any], was_false_positive: bool = True) -> str:
    """Simulate backend retraining call from dashboard interaction."""
    if feedback_loop is None or CommitFeatures is None:
        return "Mock retrain triggered (backend not available in this environment)."

    features = CommitFeatures(
        code_churn=commit["code_churn"],
        file_entropy=commit["file_entropy"],
        author_risk_score=commit["author_risk_score"],
    )
    feedback_loop.retrain_model(features, was_false_positive=was_false_positive)
    return "Retraining complete: feedback appended and model updated."


def render_dashboard() -> None:
    st.set_page_config(page_title="Shift-Left Sentinel Dashboard", layout="wide")
    st.title("🛡️ Shift-Left Sentinel — Security Metrics Demo")
    st.caption("Conference demo dashboard powered by mock scanner data and feedback simulation.")

    data = generate_mock_data()
    scorer, feedback_loop, status_message = ensure_model_ready()

    if "resolved_commits" not in st.session_state:
        st.session_state["resolved_commits"] = set()

    with st.expander("Model Status", expanded=True):
        st.info(status_message)
        if scorer is None:
            st.warning("Using UI-only simulation. Backend model classes could not be imported.")

    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Security Debt Trend")
        st.line_chart(
            data["debt_trend"],
            x="Week",
            y="Average Risk Score",
            use_container_width=True,
        )
        st.caption("Downward average risk demonstrates improving security posture over time.")

    with col2:
        st.subheader("False Positive Resolution")
        pie_df = data["false_positive_split"]
        fig, ax = plt.subplots(figsize=(5, 4))
        ax.pie(
            pie_df["Count"],
            labels=pie_df["Resolution"],
            autopct="%1.1f%%",
            startangle=90,
            colors=["#4CAF50", "#FF9800"],
            wedgeprops={"linewidth": 1, "edgecolor": "white"},
        )
        ax.axis("equal")
        st.pyplot(fig, use_container_width=True)

    st.subheader("RWCS Heatmap (Risk-Weighted Cumulative Score)")
    rwcs_df = data["rwcs_df"]
    st.dataframe(
        rwcs_df.style.background_gradient(cmap="Reds", axis=None),
        use_container_width=True,
    )
    st.caption("Darker cells indicate higher cumulative risk concentration by file and week.")

    st.divider()
    st.subheader("Review Flags")
    st.write("Flagged commits can be marked as false positives to retrain the model.")

    unresolved_commits = [
        c for c in data["flagged_commits"] if c["commit_id"] not in st.session_state["resolved_commits"]
    ]

    if not unresolved_commits:
        st.success("All flagged commits reviewed for this demo session.")
        return

    for commit in unresolved_commits:
        row_col1, row_col2, row_col3 = st.columns([4, 2, 2])
        with row_col1:
            st.markdown(
                (
                    f"**{commit['commit_id']}** | `{commit['file']}` | "
                    f"Author: {commit['author']} | Date: {commit['timestamp']}"
                )
            )
            st.caption(
                (
                    f"Risk: {commit['risk_score']} | Features — churn: {commit['code_churn']}, "
                    f"entropy: {commit['file_entropy']}, author_risk: {commit['author_risk_score']}"
                )
            )
        with row_col2:
            st.metric("Risk Score", commit["risk_score"])
        with row_col3:
            if st.button("Mark as False Positive", key=f"fp-{commit['commit_id']}"):
                message = retrain_model(feedback_loop, commit, was_false_positive=True)
                st.session_state["resolved_commits"].add(commit["commit_id"])
                st.success(f"{commit['commit_id']}: {message}")
                st.rerun()


if __name__ == "__main__":
    render_dashboard()
