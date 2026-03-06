# Conference Demo Script (5 Minutes)

## Goal
Show complete DevSecOps loop:
1. Scan code and dependencies.
2. Compute risk and enforce quality gate.
3. Persist results in SQLite.
4. Visualize real data in dashboard.
5. Feed human feedback into ML retraining.

---

## Demo Flow (Slide-by-slide)

### Slide 1 — Problem (30s)
- Traditional security checks run too late.
- Shift-Left Sentinel blocks risky changes *before merge*.

### Slide 2 — Architecture (45s)
- Scanners: Semgrep + Trivy.
- Risk engine: `risk_calculator.py`.
- Persistence: `src/data_store.py` with SQLite.
- Dashboard: `dashboard_realtime.py`.
- Feedback loop: `smart_risk_scoring.py` + `ml_feedback` table.

### Slide 3 — Live Scan Run (60s)
Run:
```bash
./run_full_scan.sh
```
Narrate:
- Semgrep + Trivy generate JSON.
- Risk calculator computes score and stores metadata.
- Merge gate behavior depends on threshold.

### Slide 4 — Real Dashboard (75s)
Open Streamlit page and show:
- latest risk score
- pass rate trend
- severity pie chart
- recent scans table
- pending flagged commits queue

### Slide 5 — Human-in-the-loop ML (60s)
- Click **Mark False Positive** in queue.
- Explain feedback is saved and model retrained.
- Show updated queue/feedback count.

### Slide 6 — CI Enforcement (30s)
- Show `.github/workflows/security-scan.yml`.
- Explain PRs to `main/develop` run scans and enforce gate via exit code.

---

## Success Metrics to Highlight
- Mean time to detect vulnerabilities (earlier in PR stage).
- Number of blocked high-risk merges.
- Trend of average risk score over time.
- False-positive handling throughput.

## Troubleshooting Cheat Sheet
- Semgrep Unicode issue on Windows:
  ```bash
  export PYTHONUTF8=1
  export PYTHONIOENCODING=utf-8
  ```
- Missing Streamlit:
  ```bash
  pip install streamlit pandas matplotlib
  ```
- No data in dashboard:
  - Ensure `python risk_calculator.py` has run at least once.

## Final Talking Points
- This is not mock data: dashboard reads real persisted scan history.
- Governance is automated: CI exit code blocks unsafe merges.
- ML becomes smarter with reviewer feedback over time.
