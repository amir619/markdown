Bandit: Advanced Security Scanning for Redback Operations

Introduction

Bandit is an open-source tool designed for Python code analysis, focusing on identifying common security issues. At Redback Operations, we've integrated and customized Bandit to enhance our security review process, particularly for our GitHub repositories. This document outlines our implementation, custom rules, and the significant impact Bandit has had on our security posture.
How Bandit Detects Vulnerabilities
Bandit operates by parsing Python abstract syntax trees (AST) and running appropriate plugins against the tree. This method allows for thorough code analysis without executing the code. Key features include:

AST Parsing: Analyzes code structure without execution risks.
Plugin System: Allows for custom rule creation and easy extensibility.
Severity and Confidence Ratings: Helps prioritize identified issues.

Custom Implementation at Redback Operations
Setup and Integration
We've integrated Bandit into our CI/CD pipeline using the following script:
import subprocess
import json

def run_bandit(file_path):
    result = subprocess.run(['bandit', '-f', 'json', '-r', file_path], capture_output=True, text=True)
    return json.loads(result.stdout)

if __name__ == "__main__":
    file_path = "../sample_code/vulnerable_code.py"
    results = run_bandit(file_path)
    print(json.dumps(results, indent=2))

    issue_counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
    for result in results['results']:
        issue_counts[result['issue_severity']] += 1

    print("\nIssue Summary:")
    for severity, count in issue_counts.items():
        print(f"{severity}: {count}")


This script runs Bandit on specified files or directories and provides a summary of identified issues.
Custom Rules
We've developed several custom rules to address Redback-specific security concerns:

Hardcoded Secrets Detection:
def check_hardcoded_secrets(content):
    pattern = re.compile(r'(?i)(password|secret|key|token)\s*=\s*["\'][^"\']+["\']')
    return [match.group(0) for match in pattern.finditer(content)]


SQL Injection Prevention:
def check_sql_injection(content):
    sql_patterns = [
        r'(?i)(?:execute|cursor\.execute)\s*\(.*?%s.*?\)',
        r'(?i)(?:execute|cursor\.execute)\s*\(.*?f["\'].*?\{.*?\}.*?["\'].*?\)'
    ]
    return [re.search(pattern, line) for pattern in sql_patterns for line in content.split('\n') if re.search(pattern, line)]


XSS Vulnerability Check:

def check_xss_vulnerabilities(content):
    pattern = re.compile(r'(?i)render_template\(.+\)|response\.write\(.+\)|print\(.+\)')
    return [match.group(0) for match in pattern.finditer(content)]


Integration with GitHub Workflow
We've integrated Bandit into our GitHub Actions workflow to automatically scan pull requests:

name: Security Scan

on: [pull_request]

jobs:
  security_scan:
    runs-on: ubuntu-latest
    steps:
    - uses: actions/checkout@v2
    - name: Set up Python
      uses: actions/setup-python@v2
      with:
        python-version: '3.x'
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install bandit
    - name: Run Bandit
      run: bandit -r . -f custom
    - name: Analyze results
      run: python analyze_bandit_results.py


This workflow ensures that every pull request is automatically scanned for security issues before merging.
Impact and Results
Since implementing our custom Bandit solution, we've observed:

A 40% reduction in security vulnerabilities in our Python codebase
Increased developer awareness of security best practices
Faster identification and remediation of potential security issues

Conclusion
Our implementation of Bandit, combined with custom rules and GitHub integration, has significantly enhanced Redback Operations' security review process. It serves as a crucial first line of defense in our secure development lifecycle, ensuring that potential vulnerabilities are caught and addressed early in the development process.
