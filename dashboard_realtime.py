"""Real-time Streamlit dashboard backed by SQLite scan history."""

from __future__ import annotations

import sqlite3
import sys
from pathlib import Path
from typing import Any, Dict, List

import matplotlib.pyplot as plt
import pandas as pd
import streamlit as st

# Make local src/ importable when running from repository root.
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from data_store import DataStore
from smart_risk_scoring import CommitFeatures, FeedbackLoop, SmartRiskScorer

DB_PATH = "security_scans.db"
MODEL_PATH = "smart_risk_model.pkl"


def get_datastore() -> DataStore:
    return DataStore(DB_PATH)


def _get_pending_flagged_commits(limit: int = 50) -> List[Dict[str, Any]]:
    """Load pending flagged commits from SQLite for human review queue."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        rows = conn.execute(
            """
            SELECT *
            FROM flagged_commits
            WHERE status = 'pending'
            ORDER BY datetime(created_at) DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def _metrics_from_scans(scans_df: pd.DataFrame) -> Dict[str, Any]:
    if scans_df.empty:
        return {
            "latest_risk": 0,
            "pass_rate": 0.0,
            "avg_risk": 0.0,
            "critical_count": 0,
        }

    latest_risk = float(scans_df.iloc[0]["risk_score"])
    pass_rate = float(scans_df["passed"].mean() * 100)
    avg_risk = float(scans_df["risk_score"].mean())
    critical_count = int(scans_df["critical_count"].sum())

    return {
        "latest_risk": round(latest_risk, 2),
        "pass_rate": round(pass_rate, 1),
        "avg_risk": round(avg_risk, 2),
        "critical_count": critical_count,
    }


def _severity_aggregate(scans_df: pd.DataFrame) -> Dict[str, int]:
    if scans_df.empty:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    return {
        "CRITICAL": int(scans_df["critical_count"].sum()),
        "HIGH": int(scans_df["high_count"].sum()),
        "MEDIUM": int(scans_df["medium_count"].sum()),
        "LOW": int(scans_df["low_count"].sum()),
    }


def _ensure_ml_feedback() -> FeedbackLoop:
    scorer = SmartRiskScorer(model_path=MODEL_PATH)
    return FeedbackLoop(scorer=scorer)


def _feature_snapshot_from_row(row: Dict[str, Any]) -> Dict[str, float]:
    """Build model-compatible feature snapshot from stored ML feature JSON data."""
    features = row.get("ml_features_json") or {}
    if isinstance(features, str):
        # Defensive: Data might be a raw JSON string if inserted outside DataStore.
        try:
            import json

            features = json.loads(features)
        except Exception:
            features = {}

    # Fallback defaults maintain compatibility even if upstream pipeline has partial features.
    return {
        "code_churn": int(features.get("code_churn", features.get("high_count", 0) * 20)),
        "file_entropy": float(features.get("file_entropy", 4.5)),
        "author_risk_score": float(features.get("author_risk_score", 0.5)),
    }


def render_dashboard() -> None:
    st.set_page_config(page_title="Shift-Left Sentinel (Realtime)", layout="wide")
    st.title("🛡️ Shift-Left Sentinel — Realtime Security Dashboard")
    st.caption("Powered by real SQLite scan data and ML feedback loop integration.")

    ds = get_datastore()
    recent_scans = ds.get_recent_scans(limit=20)
    trend_data = ds.get_trend_data(days=30)
    pending_reviews = _get_pending_flagged_commits(limit=50)

    scans_df = pd.DataFrame(recent_scans)
    trend_df = pd.DataFrame(trend_data)

    if not scans_df.empty:
        scans_df["timestamp"] = pd.to_datetime(scans_df["timestamp"], errors="coerce")
        scans_df = scans_df.sort_values("timestamp", ascending=False)

    if not trend_df.empty:
        trend_df["timestamp"] = pd.to_datetime(trend_df["timestamp"], errors="coerce")
        trend_df = trend_df.sort_values("timestamp", ascending=True)

    metrics = _metrics_from_scans(scans_df)
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Latest Risk Score", metrics["latest_risk"])
    m2.metric("Pass Rate", f"{metrics['pass_rate']}%")
    m3.metric("Average Risk", metrics["avg_risk"])
    m4.metric("Critical Findings (Recent)", metrics["critical_count"])

    st.divider()
    col1, col2 = st.columns([2, 1])

    with col1:
        st.subheader("Risk Trend (Last 30 Days)")
        if trend_df.empty:
            st.info("No scan trend data available yet. Run risk_calculator.py to populate history.")
        else:
            st.line_chart(trend_df, x="timestamp", y="risk_score", use_container_width=True)

    with col2:
        st.subheader("Severity Breakdown")
        severity = _severity_aggregate(scans_df)
        pie_df = pd.DataFrame(
            {"Severity": list(severity.keys()), "Count": list(severity.values())}
        )
        if pie_df["Count"].sum() == 0:
            st.info("No findings to visualize yet.")
        else:
            fig, ax = plt.subplots(figsize=(4, 4))
            ax.pie(
                pie_df["Count"],
                labels=pie_df["Severity"],
                autopct="%1.1f%%",
                startangle=90,
                wedgeprops={"linewidth": 1, "edgecolor": "white"},
            )
            ax.axis("equal")
            st.pyplot(fig, use_container_width=True)

    st.subheader("Recent Scans (Last 20)")
    if scans_df.empty:
        st.info("No scan rows found in database.")
    else:
        display_cols = [
            "timestamp",
            "commit_id",
            "branch",
            "author",
            "risk_score",
            "passed",
            "critical_count",
            "high_count",
            "medium_count",
            "low_count",
        ]
        existing_cols = [c for c in display_cols if c in scans_df.columns]
        st.dataframe(scans_df[existing_cols], use_container_width=True)

    st.divider()
    st.subheader("ML Review Queue (Pending Flagged Commits)")

    if not pending_reviews:
        st.success("No pending commits in review queue.")
        return

    feedback_loop = _ensure_ml_feedback()

    for row in pending_reviews:
        features = _feature_snapshot_from_row(row)
        risk_score = row.get("risk_score", 0)
        commit_id = row.get("commit_id", "unknown")
        author = row.get("author", "unknown")
        file_path = row.get("file_path", "unknown")

        c1, c2, c3 = st.columns([5, 2, 2])
        with c1:
            st.markdown(f"**{commit_id}** · `{file_path}` · Author: **{author}**")
            st.caption(
                f"Risk: {risk_score} | Features: churn={features['code_churn']}, "
                f"entropy={features['file_entropy']}, author_risk={features['author_risk_score']}"
            )
        with c2:
            st.metric("Risk", f"{risk_score}")
        with c3:
            if st.button("Mark False Positive", key=f"fp-{row['id']}"):
                commit_features = CommitFeatures(
                    code_churn=features["code_churn"],
                    file_entropy=features["file_entropy"],
                    author_risk_score=features["author_risk_score"],
                )
                feedback_loop.retrain_model(commit_features, was_false_positive=True)
                ds.save_ml_feedback(
                    commit_id=commit_id,
                    feedback_label="false_positive",
                    reviewer="dashboard_user",
                    notes="Marked from realtime dashboard",
                    feature_snapshot=features,
                )
                ds.mark_commit_reviewed(row["id"], status="false_positive")
                st.success(f"{commit_id} marked false positive and model retrained.")
                st.rerun()


if __name__ == "__main__":
    render_dashboard()
