"""SQLite persistence layer for storing security scan and ML feedback data.

This module centralizes all database operations used by the risk calculator
and real-time dashboard so scan history and review actions persist between runs.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

logger = logging.getLogger(__name__)


class DataStore:
    """SQLite wrapper that manages scan history, flagged commits, and ML feedback."""

    def __init__(self, db_path: str = "security_scans.db") -> None:
        """Initialize a new datastore and create tables if they do not exist.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self._initialize_database()

    @contextmanager
    def _get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Yield a SQLite connection with row factory and safe transaction handling."""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            logger.exception("Database error: %s", exc)
            raise
        finally:
            conn.close()

    def _initialize_database(self) -> None:
        """Create required tables and indexes for scans and ML review workflow."""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    commit_id TEXT,
                    branch TEXT,
                    author TEXT,
                    critical_count INTEGER DEFAULT 0,
                    high_count INTEGER DEFAULT 0,
                    medium_count INTEGER DEFAULT 0,
                    low_count INTEGER DEFAULT 0,
                    risk_score REAL NOT NULL,
                    passed INTEGER NOT NULL,
                    metadata_json TEXT
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS flagged_commits (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    commit_id TEXT NOT NULL,
                    file_path TEXT,
                    author TEXT,
                    risk_score REAL NOT NULL,
                    ml_features_json TEXT,
                    status TEXT NOT NULL DEFAULT 'pending',
                    reviewed_at TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS ml_feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    commit_id TEXT NOT NULL,
                    feedback_label TEXT NOT NULL,
                    reviewer TEXT,
                    notes TEXT,
                    feature_snapshot_json TEXT,
                    created_at TEXT NOT NULL DEFAULT (datetime('now'))
                )
                """
            )

            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_scans_timestamp
                ON scans(timestamp DESC)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_flagged_status
                ON flagged_commits(status)
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_feedback_commit
                ON ml_feedback(commit_id)
                """
            )

    def save_scan_result(
        self,
        *,
        timestamp: Optional[str] = None,
        commit_id: Optional[str] = None,
        branch: Optional[str] = None,
        author: Optional[str] = None,
        severity_counts: Optional[Dict[str, int]] = None,
        risk_score: float,
        passed: bool,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Insert a scan result row and return the generated ID.

        Args:
            timestamp: ISO8601 scan timestamp. Defaults to current UTC time.
            commit_id: Git commit hash associated with the scan.
            branch: Branch name associated with the scan.
            author: Commit author name.
            severity_counts: Mapping with CRITICAL/HIGH/MEDIUM/LOW counts.
            risk_score: Computed risk score from risk calculator.
            passed: Whether scan passed the threshold.
            metadata: Optional extra structured metadata.
        """
        sev = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        if severity_counts:
            sev.update({k.upper(): int(v) for k, v in severity_counts.items()})

        scan_timestamp = timestamp or datetime.utcnow().isoformat(timespec="seconds")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO scans (
                    timestamp,
                    commit_id,
                    branch,
                    author,
                    critical_count,
                    high_count,
                    medium_count,
                    low_count,
                    risk_score,
                    passed,
                    metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scan_timestamp,
                    commit_id,
                    branch,
                    author,
                    sev["CRITICAL"],
                    sev["HIGH"],
                    sev["MEDIUM"],
                    sev["LOW"],
                    float(risk_score),
                    1 if passed else 0,
                    json.dumps(metadata) if metadata else None,
                ),
            )
            return int(cursor.lastrowid)

    def get_recent_scans(self, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetch the most recent scan rows for dashboard tables."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT *
                FROM scans
                ORDER BY datetime(timestamp) DESC
                LIMIT ?
                """,
                (limit,),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    def get_trend_data(self, days: int = 30) -> List[Dict[str, Any]]:
        """Fetch risk score trend points over the last N days."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT timestamp, risk_score, passed, critical_count, high_count, medium_count, low_count
                FROM scans
                WHERE datetime(timestamp) >= datetime('now', ?)
                ORDER BY datetime(timestamp) ASC
                """,
                (f"-{int(days)} days",),
            )
            rows = cursor.fetchall()
            return [self._row_to_dict(row) for row in rows]

    def save_flagged_commit(
        self,
        *,
        commit_id: str,
        file_path: Optional[str],
        author: Optional[str],
        risk_score: float,
        ml_features: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Persist a commit flagged by the ML/risk system for human review."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO flagged_commits (
                    commit_id,
                    file_path,
                    author,
                    risk_score,
                    ml_features_json,
                    status
                ) VALUES (?, ?, ?, ?, ?, 'pending')
                """,
                (
                    commit_id,
                    file_path,
                    author,
                    float(risk_score),
                    json.dumps(ml_features) if ml_features else None,
                ),
            )
            return int(cursor.lastrowid)

    def mark_commit_reviewed(self, flagged_id: int, status: str = "reviewed") -> bool:
        """Update a flagged commit to reviewed/false_positive and set review timestamp."""
        allowed_status = {"reviewed", "false_positive", "confirmed"}
        if status not in allowed_status:
            raise ValueError(f"Invalid status '{status}'. Allowed values: {sorted(allowed_status)}")

        reviewed_at = datetime.utcnow().isoformat(timespec="seconds")

        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE flagged_commits
                SET status = ?, reviewed_at = ?
                WHERE id = ?
                """,
                (status, reviewed_at, int(flagged_id)),
            )
            return cursor.rowcount > 0

    def save_ml_feedback(
        self,
        *,
        commit_id: str,
        feedback_label: str,
        reviewer: Optional[str] = None,
        notes: Optional[str] = None,
        feature_snapshot: Optional[Dict[str, Any]] = None,
    ) -> int:
        """Record reviewer feedback used to retrain or tune ML behavior."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO ml_feedback (
                    commit_id,
                    feedback_label,
                    reviewer,
                    notes,
                    feature_snapshot_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (
                    commit_id,
                    feedback_label,
                    reviewer,
                    notes,
                    json.dumps(feature_snapshot) if feature_snapshot else None,
                ),
            )
            return int(cursor.lastrowid)

    @staticmethod
    def _row_to_dict(row: sqlite3.Row) -> Dict[str, Any]:
        """Convert sqlite Row objects to normal dicts with decoded JSON fields."""
        data = dict(row)
        for key in ("metadata_json", "ml_features_json", "feature_snapshot_json"):
            if key in data and data[key]:
                try:
                    data[key] = json.loads(data[key])
                except json.JSONDecodeError:
                    logger.warning("Failed to decode JSON field '%s'", key)
        if "passed" in data:
            data["passed"] = bool(data["passed"])
        return data
