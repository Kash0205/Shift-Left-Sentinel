import json
import math
import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Make local src/ importable when running from repository root.
REPO_ROOT = Path(__file__).resolve().parent
SRC_DIR = REPO_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.append(str(SRC_DIR))

from data_store import DataStore
from project_config import get_risk_threshold

# Centralized risk threshold from config/project_config.json
RISK_THRESHOLD = get_risk_threshold()

# Mapping severity labels to risk points
SEVERITY_WEIGHTS = {
    "CRITICAL": 40,
    "HIGH": 25,
    "ERROR": 25,  # Semgrep uses "ERROR" for high severity
    "MEDIUM": 10,
    "WARNING": 10,  # Semgrep uses "WARNING"
    "LOW": 5,
    "INFO": 1,
    "UNKNOWN": 0,
}

# NEW: Context Multipliers (The "Intelligence" Layer)
# If a file path matches these keywords, multiply the score.
CONTEXT_MULTIPLIERS = {
    "production": 1.0,  # Standard code
    "test": 0.1,  # Test files (Low risk)
    "docs": 0.0,  # Documentation (Zero risk)
    "config": 1.5,  # Config files (High risk for secrets!)
    "dependencies": 2.0,  # requirements.txt, package.json (VERY HIGH RISK!)
    "infrastructure": 2.0,  # Pipeline files (Extreme risk!)
}


def get_context_multiplier(filepath):
    """
    Analyzes the file path to determine its 'Risk Context'.
    """
    filepath = str(filepath).lower()

    # Priority Checks (order matters!)

    # Check for dependency files FIRST (before .txt check)
    if any(
        x in filepath
        for x in ["requirements.txt", "package.json", "package-lock.json", "pom.xml", "go.mod"]
    ):
        return CONTEXT_MULTIPLIERS["dependencies"]

    if any(x in filepath for x in ["test/", "tests/", "_test.py", ".spec.js"]):
        return CONTEXT_MULTIPLIERS["test"]

    # Now check for docs (but requirements.txt already handled above)
    if any(x in filepath for x in [".md", "readme", "docs/", "documentation/"]):
        return CONTEXT_MULTIPLIERS["docs"]

    if any(x in filepath for x in ["dockerfile", "docker-compose", ".github/", "jenkinsfile", ".gitlab-ci"]):
        return CONTEXT_MULTIPLIERS["infrastructure"]

    if any(x in filepath for x in ["config", ".env", "settings.py", ".yaml", ".yml"]):
        return CONTEXT_MULTIPLIERS["config"]

    # Default to production code
    return CONTEXT_MULTIPLIERS["production"]


# -------Parses Semgrep JSON output-------

def parse_semgrep(filename):
    """Reads Semgrep JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Iterate through the "results" list in Semgrep output
        for result in data.get("results", []):
            issue = {
                "tool": "Semgrep",
                "rule_id": result.get("check_id"),
                "file": result.get("path"),
                # Semgrep uses ERROR/WARNING/INFO. We map them later.
                "severity": result.get("extra", {}).get("severity", "UNKNOWN"),
                "message": result.get("extra", {}).get("message"),
            }
            issues.append(issue)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping Semgrep scan.")
    except json.JSONDecodeError:
        print(f"Error: {filename} is empty or invalid JSON. Skipping.")
    return issues


# -------Parses Trivy JSON output-------

def parse_trivy(filename):
    """Reads Trivy JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, "r", encoding="utf-8") as f:
            data = json.load(f)

        # Trivy structure is nested: Results -> Vulnerabilities
        if "Results" in data:
            for target in data["Results"]:
                for vuln in target.get("Vulnerabilities", []):
                    issue = {
                        "tool": "Trivy",
                        "rule_id": vuln.get("VulnerabilityID"),
                        "file": target.get("Target"),
                        # Trivy uses CRITICAL/HIGH/MEDIUM/LOW
                        "severity": vuln.get("Severity", "UNKNOWN"),
                        "message": vuln.get("Description"),
                    }
                    issues.append(issue)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping Trivy scan.")
    except json.JSONDecodeError:
        print(f"Error: {filename} is empty or invalid JSON. Skipping.")
    return issues


# -------Parses Gitleaks JSON output-------
def calculate_shannon_entropy(data):
    """Calculates the Shannon entropy of a string."""
    if not data:
        return 0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += -p_x * math.log(p_x, 2)
    return entropy


# -------Determines if a string is high entropy-------

def is_high_entropy(secret_string, threshold=4.5):
    """
    Returns True if the string looks random (high entropy).
    Standard English text usually has entropy between 3.5 and 4.5.
    API keys/Secrets usually have entropy > 4.5.
    """
    return calculate_shannon_entropy(secret_string) > threshold


def get_git_info():
    """Return commit metadata for the current repository.

    Falls back to "unknown" values if the current folder is not a git repository
    or if any git command fails in CI/local environments.
    """

    def _run_git_command(args, default="unknown"):
        try:
            value = subprocess.check_output(args, stderr=subprocess.DEVNULL, text=True).strip()
            return value or default
        except Exception:
            return default

    return {
        "commit_id": _run_git_command(["git", "rev-parse", "HEAD"]),
        "branch": _run_git_command(["git", "rev-parse", "--abbrev-ref", "HEAD"]),
        "author": _run_git_command(["git", "log", "-1", "--pretty=format:%an"]),
    }


def normalize_severity(severity):
    """Normalize tool-specific severities into CRITICAL/HIGH/MEDIUM/LOW buckets."""
    sev = (severity or "UNKNOWN").upper()
    if sev == "ERROR":
        return "HIGH"
    if sev == "WARNING":
        return "MEDIUM"
    if sev in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}:
        return sev
    if sev == "INFO":
        return "LOW"
    return "LOW"


def count_by_severity(issues):
    """Count findings by normalized severity levels."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for issue in issues:
        bucket = normalize_severity(issue.get("severity"))
        counts[bucket] += 1
    return counts


# -------Calculates Risk Score-------

def calculate_risk_score(issues):
    total_score = 0
    max_possible_score = len(issues) * 40 * 2.0
    print("\n--- Risk Calculation Details (Context-Aware) ---")

    for issue in issues:
        # Step 1: Base Severity
        severity = issue.get("severity", "UNKNOWN").upper()
        base_weight = SEVERITY_WEIGHTS.get(severity, 0)

        # Step 2: Context Analysis
        file_path = issue.get("file", "unknown")
        multiplier = get_context_multiplier(file_path)

        # Step 3: Final Score
        final_weight = int(base_weight * multiplier)

        # Logging for the user (and for you to debug)
        print(f"[{severity}] in '{file_path}'")
        print(f"   ↳ Base: {base_weight} x Context: {multiplier} = {final_weight} pts")

        total_score += final_weight

    # Normalize to 0-100
    if max_possible_score > 0:
        normalized_score = min(100, (total_score / max_possible_score) * 100)
    else:
        normalized_score = 0

    return int(normalized_score)


def maybe_flag_commit_for_review(data_store, git_info, severity_counts, total_risk_score):
    """Save a pending ML review item when scan indicates potentially risky changes."""
    if total_risk_score <= RISK_THRESHOLD and severity_counts["CRITICAL"] == 0:
        return

    # Basic feature snapshot for downstream dashboard/ML review workflows.
    ml_features = {
        "critical_count": severity_counts["CRITICAL"],
        "high_count": severity_counts["HIGH"],
        "medium_count": severity_counts["MEDIUM"],
        "low_count": severity_counts["LOW"],
        "risk_score": total_risk_score,
        "scan_time": datetime.utcnow().isoformat(timespec="seconds"),
    }

    data_store.save_flagged_commit(
        commit_id=git_info["commit_id"],
        file_path="repository",
        author=git_info["author"],
        risk_score=float(total_risk_score),
        ml_features=ml_features,
    )


def main():
    print("--- Shift-Left Sentinel: Risk Calculator ---")

    # 1. Ingest Data
    semgrep_issues = parse_semgrep("semgrep_output.json")
    trivy_issues = parse_trivy("trivy_output.json")
    all_issues = semgrep_issues + trivy_issues

    print(f"\nSuccessfully loaded {len(all_issues)} issues.")

    # 2. Calculate Risk
    total_risk_score = calculate_risk_score(all_issues)
    severity_counts = count_by_severity(all_issues)

    git_info = get_git_info()
    passed = total_risk_score <= RISK_THRESHOLD

    # 3. Persist result for dashboard and trend views
    data_store = DataStore()
    data_store.save_scan_result(
        timestamp=datetime.utcnow().isoformat(timespec="seconds"),
        commit_id=git_info["commit_id"],
        branch=git_info["branch"],
        author=git_info["author"],
        severity_counts=severity_counts,
        risk_score=float(total_risk_score),
        passed=passed,
        metadata={"issue_count": len(all_issues)},
    )
    maybe_flag_commit_for_review(data_store, git_info, severity_counts, total_risk_score)

    print("\n------------------------------------------------")
    print(f"TOTAL RISK SCORE: {total_risk_score} / 100 (Scale)")
    print(f"RISK THRESHOLD:   {RISK_THRESHOLD}")
    print(
        "SEVERITY COUNTS: "
        f"CRITICAL={severity_counts['CRITICAL']} HIGH={severity_counts['HIGH']} "
        f"MEDIUM={severity_counts['MEDIUM']} LOW={severity_counts['LOW']}"
    )
    print(f"GIT METADATA:     {git_info['commit_id'][:8]} | {git_info['branch']} | {git_info['author']}")
    print("------------------------------------------------")

    # 4. The Decision Gate (Enforcement Module)
    if total_risk_score > RISK_THRESHOLD:
        print(" DECISION: BLOCK MERGE (Risk too high)")
        sys.exit(1)  # This tells GitHub Actions to FAIL the pipeline
    else:
        print(" DECISION: ALLOW MERGE (Risk within limits)")
        sys.exit(0)  # This tells GitHub Actions to PASS


if __name__ == "__main__":
    main()
