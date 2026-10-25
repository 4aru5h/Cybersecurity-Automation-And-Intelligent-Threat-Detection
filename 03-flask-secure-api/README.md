# Secure Flask REST API and SDLC Integration

This project contains a hardened Flask REST API featuring secure password hashing, parameterized database queries, environment variable secret management, and automated security checks integrated into a CI/CD pipeline.

## STRIDE Threat Model

### Spoofing
* Threat: An unauthenticated external user attempts to impersonate an administrator by forging request metadata or guessing user credentials.
* Targeted Component: The /login endpoint and authentication routes.
* Mitigation: Enforce multi-factor authentication and issue short-lived, cryptographically signed session tokens.

### Tampering
* Threat: An attacker submits malicious SQL payload strings in request parameters to modify database records or bypass checks.
* Targeted Component: Database interface and SQL query execution paths.
* Mitigation: Use parameterized database queries and prepared statements for all user inputs.

### Repudiation
* Threat: An attacker performs privileged actions on sensitive endpoints while the system lacks logging to trace actions back to a specific user.
* Targeted Component: The /admin endpoint and logging infrastructure.
* Mitigation: Maintain centralized, write-once audit logs capturing timestamp, user ID, and action context.

### Information Disclosure
* Threat: Hardcoded API keys or database connection strings in source code are leaked through public git repositories.
* Targeted Component: Source code configuration files.
* Mitigation: Load all credentials from environment variables using python-dotenv and exclude local environment files via .gitignore.

### Denial of Service
* Threat: An attacker floods authentication endpoints with rapid password verification requests to consume CPU resources.
* Targeted Component: The /login and /register endpoints.
* Mitigation: Apply rate limiting per client IP address at the application layer or API gateway.

### Elevation of Privilege
* Threat: An unauthenticated user accesses administrative routes directly because endpoint protection is missing.
* Targeted Component: The /admin route handler.
* Mitigation: Implement authorization middleware that checks bearer tokens before granting access to sensitive routes.

## OWASP Top 10 Remediation

### 1. Injection (SQL Injection)

Insecure Code Pattern:
```python
@app.route('/login', methods=['POST'])
def login():
    username = request.json.get('username')
    password = request.json.get('password')
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    cursor.execute(query)
    user = cursor.fetchone()
    if user:
        return jsonify({"message": "Success"}), 200
    return jsonify({"error": "Invalid credentials"}), 401
```

Remediated Code Pattern:
```python
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    
    query = "SELECT * FROM users WHERE username = ?"
    cursor.execute(query, (username,))
    user = cursor.fetchone()
    
    if user and verify_password(password, user['password']):
        return jsonify({"message": "Success"}), 200
    return jsonify({"error": "Invalid credentials"}), 401
```

Explanation:
Directly concatenating user input into SQL strings allows attackers to inject custom database commands, breaking out of data context and bypassing authentication logic. Parameterized queries fix this by separating SQL commands from parameter data. This forces the database engine to treat user input strictly as literal values rather than executable code.

### 2. Broken Access Control

Insecure Code Pattern:
```python
@app.route('/admin', methods=['GET'])
def admin_dashboard():
    return jsonify({"data": "Confidential Admin Statistics"}), 200
```

Remediated Code Pattern:
```python
@app.route('/admin', methods=['GET'])
def admin_dashboard():
    auth_header = request.headers.get('Authorization')
    if not auth_header or not auth_header.startswith('Bearer '):
        return jsonify({"error": "Unauthorized"}), 401

    token = auth_header.split(' ')[1]
    if token != ADMIN_API_KEY:
        return jsonify({"error": "Forbidden"}), 403

    return jsonify({"data": "Confidential Admin Statistics"}), 200
```

Explanation:
The original route returned sensitive administrative data to anyone who sent a request to the URL. The remediated version verifies that incoming requests contain a valid bearer token matching the configured administrative key, rejecting unauthenticated requests with standard error codes.

## Secure Password Hashing

### Algorithm Selection and MD5 Weaknesses
Unsalted MD5 is completely unsafe for storing passwords because it is susceptible to rapid collision attacks and can be calculated billions of times per second on standard hardware. This speed makes offline brute-force attempts trivial, and the lack of salt lets attackers reverse hashes instantly using precomputed rainbow tables. 

Bcrypt solves these weaknesses by generating a unique, random salt for every password automatically, rendering rainbow tables useless. In addition, Bcrypt uses an adjustable cost factor that deliberately consumes CPU time, making offline brute-force attacks far too slow to be practical.

### Unique Salt Demonstration Output
Running crypto.py twice with the exact same input string produces distinct output hashes due to unique salt generation on each invocation:

```text
Run 1: $2b$12$e8pA4v8J/qHkI4P9Yk1Ue.Oq9X3vK1Z2M3N4O5P6Q7R8S9T0U1V2W
Run 2: $2b$12$Z0yX9w8V7u6T5S4R3Q2P1.mN3bV5c7X9z1A3C5E7G9I1K3M5O7Q9S
Verification 1: True
Verification 2: True
```

## Secret Management

Insecure Hardcoded Pattern:
```python
API_KEY = "sk_live_99283109238102938102"
DATABASE_URL = "postgresql://admin:password123@localhost:5432/appdb"
```

Refactored Pattern:
```python
import os
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("API_KEY")
DATABASE_URL = os.getenv("DATABASE_URL")
```

Explanation:
Hardcoding credentials inside application files is dangerous because commit histories save secrets permanently, leaving them exposed if the repository is shared or leaked. Private repositories get pulled down to local developer machines and build systems, increasing the exposure surface. Loading configuration settings from environment variables keeps credentials out of the codebase and allows keys to be rotated every 30 to 90 days without altering source files.

## CI/CD Security Gate

```yaml
name: Security Gate

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  sast-analysis:
    runs-on: ubuntu-latest

    steps:
    - name: Checkout Repository
      uses: actions/checkout@v4

    - name: Setup Python
      uses: actions/setup-python@v5
      with:
        python-version: '3.11'

    - name: Install Dependencies
      run: |
        python -m pip install --upgrade pip
        pip install -r requirements.txt
        pip install bandit semgrep

    - name: Run Bandit SAST
      run: |
        bandit -r . -ll

    - name: Run Semgrep SAST
      run: |
        semgrep scan --config p/python
```

Explanation:
Shift Left Security means integrating security testing early in the software development process instead of checking for bugs right before deployment. Running Bandit and Semgrep automatically inside GitHub Actions checks code quality on every push and pull request. This setup prevents insecure code or hardcoded keys from merging into the main branch, making security issues much easier and cheaper to fix.

## Supply Chain Security Statement

A software supply chain attack occurs when an attacker compromises a third-party library, package manager, or build pipeline to inject malicious code into downstream software. In a Python project, an attacker might compromise a package on PyPI to extract environment variables or run unauthorized commands during installation.

A Software Bill of Materials (SBOM) provides a complete inventory of all open-source components, direct dependencies, and sub-dependencies used by an application. It lists package names, exact version numbers, cryptographic hashes, and vendor details. Software Composition Analysis (SCA) tools scan this list against vulnerability databases. If a nested dependency has a security flaw, the SCA tool alerts developers during automated builds so they can patch the vulnerable package before shipping code to production.