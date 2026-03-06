import json
import sys
import math
import re

# Configuration: We will tweak these later in Phase 2
RISK_THRESHOLD = 80

# Mapping severity labels to risk points
SEVERITY_WEIGHTS = {
    'CRITICAL': 40,
    'HIGH': 25,
    'ERROR': 25,    # Semgrep uses "ERROR" for high severity
    'MEDIUM': 10,
    'WARNING': 10,  # Semgrep uses "WARNING"
    'LOW': 5,
    'INFO': 1,
    'UNKNOWN': 0
}

# NEW: Context Multipliers (The "Intelligence" Layer)
# If a file path matches these keywords, multiply the score.
CONTEXT_MULTIPLIERS = {
    'production': 1.0,  # Standard code
    'test': 0.1,        # Test files (Low risk)
    'docs': 0.0,        # Documentation (Zero risk)
    'config': 1.5,      # Config files (High risk for secrets!)
    'ci_cd': 2.0        # Pipeline files (Extreme risk!)
}

def get_context_multiplier(filepath):
    """
    Analyzes the file path to determine its 'Risk Context'.
    """
    filepath = str(filepath).lower()
    
    # Priority Checks
    if any(x in filepath for x in ['test/', 'tests/', '_test.py', '.spec.js']):
        return CONTEXT_MULTIPLIERS['test']
    
    if any(x in filepath for x in ['.md', '.txt', 'docs/']):
        return CONTEXT_MULTIPLIERS['docs']
        
    if any(x in filepath for x in ['dockerfile', 'docker-compose', '.github/', 'jenkinsfile']):
        return CONTEXT_MULTIPLIERS['infrastructure']
        
    if any(x in filepath for x in ['config', '.env', 'settings.py']):
        return CONTEXT_MULTIPLIERS['config']
        
    # Default to production code
    return CONTEXT_MULTIPLIERS['production']

#-------Parses Semgrep JSON output-------

def parse_semgrep(filename):
    """Reads Semgrep JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            
        # Iterate through the "results" list in Semgrep output
        for result in data.get('results', []):
            issue = {
                'tool': 'Semgrep',
                'rule_id': result.get('check_id'),
                'file': result.get('path'),
                # Semgrep uses ERROR/WARNING/INFO. We map them later.
                'severity': result['extra'].get('severity', 'UNKNOWN'),
                'message': result['extra'].get('message')
            }
            issues.append(issue)
    except FileNotFoundError:
        print(f"Warning: {filename} not found. Skipping Semgrep scan.")
    except json.JSONDecodeError:
        print(f"Error: {filename} is empty or invalid JSON. Skipping.")
    return issues

#-------Parses Trivy JSON output-------

def parse_trivy(filename):
    """Reads Trivy JSON and returns a list of standardized issues."""
    issues = []
    try:
        with open(filename, 'r') as f:
            data = json.load(f)
            
        # Trivy structure is nested: Results -> Vulnerabilities
        if 'Results' in data:
            for target in data['Results']:
                for vuln in target.get('Vulnerabilities', []):
                    issue = {
                        'tool': 'Trivy',
                        'rule_id': vuln.get('VulnerabilityID'),
                        'file': target.get('Target'),
                        # Trivy uses CRITICAL/HIGH/MEDIUM/LOW
                        'severity': vuln.get('Severity', 'UNKNOWN'),
                        'message': vuln.get('Description')
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
            entropy += - p_x * math.log(p_x, 2)
    return entropy

#-------Determines if a string is high entropy-------

def is_high_entropy(secret_string, threshold=4.5):
    """
    Returns True if the string looks random (high entropy).
    Standard English text usually has entropy between 3.5 and 4.5.
    API keys/Secrets usually have entropy > 4.5.
    """
    return calculate_shannon_entropy(secret_string) > threshold

#-------Calculates Risk Score-------

def calculate_risk_score(issues):
    total_score = 0
    print("\n--- Risk Calculation Details (Context-Aware) ---")

    for issue in issues:
        # Step 1: Base Severity
        severity = issue.get('severity', 'UNKNOWN').upper()
        base_weight = SEVERITY_WEIGHTS.get(severity, 0)
        
        # Step 2: Context Analysis
        file_path = issue.get('file', 'unknown')
        multiplier = get_context_multiplier(file_path)
        
        # Step 3: Final Score
        final_weight = int(base_weight * multiplier)
        
        # Logging for the user (and for you to debug)
        print(f"[{severity}] in '{file_path}'")
        print(f"   ↳ Base: {base_weight} x Context: {multiplier} = {final_weight} pts")
        
        total_score += final_weight

    return total_score

def main():
    print("--- Shift-Left Sentinel: Risk Calculator ---")
    
    if len(sys.argv) < 3:
        print("Usage: python3 risk_engine.py <semgrep_json> <trivy_json>")
        sys.exit(1)

    # Take inputs from the command line instead of hardcoding
    semgrep_file = sys.argv[1]
    trivy_file = sys.argv[2]
    
    # 1. Ingest Data using the user-provided filenames
    semgrep_issues = parse_semgrep(semgrep_file)
    trivy_issues = parse_trivy(trivy_file)
    all_issues = semgrep_issues + trivy_issues
    
    print(f"\nAnalyzing: {semgrep_file} and {trivy_file}")
    print(f"Successfully loaded {len(all_issues)} issues.")
    
    # 2. Calculate Risk
    total_risk_score = calculate_risk_score(all_issues)
    
    print("\n------------------------------------------------")
    print(f"TOTAL RISK SCORE: {total_risk_score} / 100 (Scale)")
    print(f"RISK THRESHOLD:   {RISK_THRESHOLD}")
    print("------------------------------------------------")

    # 3. The Decision Gate (Enforcement Module)
    if total_risk_score > RISK_THRESHOLD:
        print(" DECISION: BLOCK MERGE (Risk too high)")
        sys.exit(1) # This tells GitHub Actions to FAIL the pipeline
    else:
        print(" DECISION: ALLOW MERGE (Risk within limits)")
        sys.exit(0) # This tells GitHub Actions to PASS

if __name__ == "__main__":
    main()
