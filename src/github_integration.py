"""Git metadata extraction utilities for risk scoring and ML features.

This module provides repository-level feature extraction that can be used by
risk calculation pipelines, dashboards, or model training workflows.
"""

from __future__ import annotations

import math
import subprocess
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional, Tuple


@dataclass
class CommitMetadata:
    """Structured metadata extracted for a single commit."""

    commit_hash: str
    author: str
    email: str
    timestamp: str
    branch: str
    changed_files: List[str]
    insertions: int
    deletions: int
    code_churn: int
    author_risk_score: float
    file_entropy: float


class GitHubIntegration:
    """Helper for extracting rich commit metadata from git history."""

    SENSITIVE_PATH_KEYWORDS = (
        ".github/",
        "dockerfile",
        "docker-compose",
        "requirements.txt",
        "package.json",
        "infra",
        "terraform",
        ".env",
        "config",
    )

    def __init__(self, repo_root: Optional[str] = None) -> None:
        self.repo_root = Path(repo_root or ".").resolve()

    def extract_commit_features(self, commit_ref: str = "HEAD") -> CommitMetadata:
        """Collect complete feature metadata for a given commit reference."""
        commit_hash = self._git(["rev-parse", commit_ref])
        branch = self._git(["rev-parse", "--abbrev-ref", commit_ref])

        commit_line = self._git(
            ["show", "-s", "--format=%H|%an|%ae|%aI", commit_hash]
        )
        parts = commit_line.split("|", 3)
        if len(parts) != 4:
            raise RuntimeError("Unable to parse commit metadata from git show output")

        _, author, email, timestamp = parts

        changed_files = self.get_changed_files(commit_hash)
        insertions, deletions = self.get_code_churn(commit_hash)
        code_churn = insertions + deletions

        author_risk_score = self.calculate_author_risk_score(author_email=email)
        file_entropy = self.calculate_file_entropy(changed_files)

        return CommitMetadata(
            commit_hash=commit_hash,
            author=author,
            email=email,
            timestamp=timestamp,
            branch=branch,
            changed_files=changed_files,
            insertions=insertions,
            deletions=deletions,
            code_churn=code_churn,
            author_risk_score=author_risk_score,
            file_entropy=file_entropy,
        )

    def get_changed_files(self, commit_ref: str = "HEAD") -> List[str]:
        """Return list of changed file paths for a commit."""
        output = self._git(["show", "--pretty=format:", "--name-only", commit_ref])
        files = [line.strip() for line in output.splitlines() if line.strip()]
        return files

    def get_code_churn(self, commit_ref: str = "HEAD") -> Tuple[int, int]:
        """Return insertions and deletions for a commit via git numstat."""
        output = self._git(["show", "--pretty=format:", "--numstat", commit_ref])
        insertions = 0
        deletions = 0

        for line in output.splitlines():
            parts = line.strip().split("\t")
            if len(parts) < 3:
                continue
            add_raw, del_raw = parts[0], parts[1]

            # Binary files are represented as '-'.
            if add_raw.isdigit():
                insertions += int(add_raw)
            if del_raw.isdigit():
                deletions += int(del_raw)

        return insertions, deletions

    def calculate_author_risk_score(
        self,
        author_email: str,
        history_limit: int = 50,
    ) -> float:
        """Estimate author risk from recent commit patterns (0.0 to 1.0).

        Heuristic factors:
        - large average churn implies potentially risky changes
        - ratio of commits touching sensitive paths
        - commit frequency (more commits -> slightly higher baseline weight)
        """
        output = self._git(
            ["log", f"--author={author_email}", f"-n{history_limit}", "--pretty=format:%H"]
        )
        commits = [line.strip() for line in output.splitlines() if line.strip()]
        if not commits:
            return 0.2

        churn_values = []
        sensitive_hits = 0

        for commit in commits:
            ins, dels = self.get_code_churn(commit)
            churn_values.append(ins + dels)
            files = self.get_changed_files(commit)
            if any(self._is_sensitive_path(f) for f in files):
                sensitive_hits += 1

        avg_churn = sum(churn_values) / max(1, len(churn_values))
        churn_score = min(1.0, avg_churn / 500.0)
        sensitive_ratio = sensitive_hits / len(commits)
        frequency_score = min(1.0, len(commits) / float(history_limit))

        risk_score = (0.45 * churn_score) + (0.4 * sensitive_ratio) + (0.15 * frequency_score)
        return round(min(1.0, max(0.0, risk_score)), 3)

    def calculate_file_entropy(self, files: List[str]) -> float:
        """Compute Shannon entropy based on changed file extensions and names."""
        if not files:
            return 0.0

        tokens: List[str] = []
        for file_path in files:
            p = Path(file_path)
            ext = p.suffix.lower() or "<none>"
            tokens.append(ext)
            tokens.extend(part.lower() for part in p.parts)

        counts = Counter(tokens)
        total = sum(counts.values())
        entropy = 0.0
        for count in counts.values():
            probability = count / total
            entropy -= probability * math.log(probability, 2)

        return round(entropy, 4)

    def _is_sensitive_path(self, file_path: str) -> bool:
        path = file_path.lower()
        return any(keyword in path for keyword in self.SENSITIVE_PATH_KEYWORDS)

    def _git(self, args: List[str]) -> str:
        result = subprocess.run(
            ["git"] + args,
            cwd=str(self.repo_root),
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Git command failed: git {' '.join(args)}\n"
                f"stdout: {result.stdout}\nstderr: {result.stderr}"
            )
        return result.stdout.strip()
