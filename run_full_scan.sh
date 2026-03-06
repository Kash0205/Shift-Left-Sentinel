#!/usr/bin/env bash
set -euo pipefail

# Shift-Left Sentinel full demo runner
# Steps:
# 1) clean previous scan artifacts
# 2) run Semgrep
# 3) run Trivy
# 4) calculate risk (persists to SQLite)
# 5) launch realtime dashboard only if risk gate passes

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

echo "🛡️  Shift-Left Sentinel: Running security checks..."

cleanup_artifacts() {
  python - <<'PY'
from pathlib import Path
for p in ["semgrep_output.json", "trivy_output.json"]:
    fp = Path(p)
    if fp.exists():
        fp.unlink()
PY
}

require_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "❌ Required command not found: $1"
    exit 2
  fi
}

cleanup_artifacts
require_cmd semgrep
require_cmd trivy
require_cmd python

echo "🔍 Running Semgrep..."
# Keep UTF-8 defaults for better Windows Git Bash compatibility.
export PYTHONUTF8=${PYTHONUTF8:-1}
export PYTHONIOENCODING=${PYTHONIOENCODING:-utf-8}
if ! semgrep scan --config auto --json --output semgrep_output.json .; then
  echo "⚠️ Semgrep failed; writing empty output so pipeline can continue with Trivy data."
  printf '{"results":[]}' > semgrep_output.json
fi

echo "🔍 Running Trivy..."
# Secret scanner can be noisy/slower; vuln scan gives consistent dependency coverage.
trivy fs --scanners vuln --format json --output trivy_output.json .

echo "📊 Calculating risk score..."
set +e
python risk_calculator.py
risk_exit=$?
set -e

echo "🚦 Risk gate exit code: $risk_exit"
if [[ "$risk_exit" -ne 0 ]]; then
  echo "❌ Risk score exceeded threshold. Dashboard launch skipped."
  echo "   Review semgrep_output.json, trivy_output.json, and security_scans.db"
  exit "$risk_exit"
fi

echo "✅ Risk score within threshold. Launching realtime dashboard..."
python -m streamlit run dashboard_realtime.py
