# Installation Guide (Windows, macOS, Linux)

This guide sets up Shift-Left Sentinel end-to-end for local execution.

## 1) Prerequisites
- Python 3.8+
- Git
- Semgrep CLI
- Trivy CLI

## 2) Clone and enter repo
```bash
git clone https://github.com/Divyam416/Shift-Left-Sentinel.git
cd Shift-Left-Sentinel
```

## 3) Create virtual environment

### Windows (Git Bash)
```bash
python -m venv .venv
source .venv/Scripts/activate
```

### macOS / Linux
```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4) Install Python dependencies
```bash
python -m pip install --upgrade pip
pip install -r src/requirements.txt
pip install streamlit pandas matplotlib
```

## 5) Verify tool availability
```bash
python --version
semgrep --version
trivy --version
```

## 6) Run full scan + dashboard
```bash
./run_full_scan.sh
```

### Expected behavior
- If risk score is above threshold, script exits non-zero and blocks dashboard startup.
- If risk score is within threshold, Streamlit dashboard launches automatically.

## 7) Manual run (optional)
```bash
semgrep scan --config auto --json --output semgrep_output.json .
trivy fs --scanners vuln --format json --output trivy_output.json .
python risk_calculator.py
python -m streamlit run dashboard_realtime.py
```

## 8) Validate persistence layer
```bash
python - <<'PY'
import sqlite3
conn = sqlite3.connect('security_scans.db')
cur = conn.cursor()
print(cur.execute("select name from sqlite_master where type='table'").fetchall())
print('scans:', cur.execute('select count(*) from scans').fetchone()[0])
print('flagged:', cur.execute("select count(*) from flagged_commits").fetchone()[0])
print('feedback:', cur.execute("select count(*) from ml_feedback").fetchone()[0])
conn.close()
PY
```
