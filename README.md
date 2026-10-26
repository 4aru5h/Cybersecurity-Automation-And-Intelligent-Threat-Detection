# Cybersecurity Capstone: Threat Detection, Security Automation & Hardened Infrastructure

<p align="left">
  <img src="https://github.com/4aru5h/Cybersecurity-Automation-And-Intelligent-Threat-Detection/actions/workflows/security.yml/badge.svg" alt="DevSecOps Security Gate" />
  <img src="https://github.com/4aru5h/Cybersecurity-Automation-And-Intelligent-Threat-Detection/actions/workflows/codeql.yml/badge.svg" alt="CodeQL Scan" />
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" alt="Python 3.11" />
  <img src="https://img.shields.io/badge/Security-STRIDE_Threat_Model-red" alt="STRIDE" />
  <img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="License" />
</p>

An end-to-end cybersecurity suite built as a senior capstone project for computer engineering at MPSTME, NMIMS. Combines security operations automation, machine learning threat detection, a full PTES-compliant penetration testing audit against an isolated lab subnet, and a cryptographically hardened REST API.

---

## Architecture Overview

```text
                                +-------------------------------------------+
                                |          Target Lab Network Subnet        |
                                |               (192.168.56.0/24)           |
                                +-------------------------------------------+
                                                      |
                  +-----------------------------------+-----------------------------------+
                  |                                   |                                   |
                  v                                   v                                   v
        +-------------------+               +-------------------+               +-------------------+
        |  Attacker System  |               |  Authoritative    |               | Vulnerable Target |
        |  Kali Linux 2024  | ------------> |  BIND9 DNS Server | ------------> |  Metasploitable 2 |
        |  (192.168.56.10)  |  Zone XFR/    |  (192.168.56.15)  |  SYN Scans/   |  (192.168.56.20)  |
        +-------------------+  Port Scans   +-------------------+  Exploit Path +-------------------+
                  |                                                                       |
                  |                                                                       |
                  v                                                                       v
        +-------------------+                                                   +-------------------+
        | Security Tooling  |                                                   | Hardened Flask    |
        | - TCP Port Scanner|                                                   | Service (Module 3)|
        | - VT Intelligence |                                                   | - STRIDE Model    |
        | - Dual ML Models  |                                                   | - Bcrypt Auth     |
        +-------------------+                                                   +-------------------+
```

---

## Modules Summary

### Module 01: Python Security Automation & Machine Learning
Located in `01-python-security-automation-ml/`:
- **Multithreaded Port Scanner (`port_scanner.py`):** High-speed TCP port scanner with `ThreadPoolExecutor` thread pools, socket timeout controls, service banner extraction, single/range/list port parsing, and formatted reporting.
- **Log Enrichment Engine (`log_enricher.py`):** Parses authentication and web access logs, extracts public IPv4 indicators (RFC-compliant via `ipaddress`), and enriches them via `ip-api.com`.
- **Threat Intelligence Integrator (`virustotal_check.py`):** Interfaces with the VirusTotal REST API v3 to enrich IP indicators with reputation scores, with built-in `--mock` demonstration support.
- **Dual-Model ML Threat Detector (`ml_threat_detector.py`):**
  - Synthetic Benchmark Mode: Compares Supervised `RandomForestClassifier` vs Unsupervised `IsolationForest` on a 5,000-sample benchmark dataset.
  - Log Inference Mode (`--input sample_logs.txt`): Extracts numerical security features from firewall and authentication logs to classify anomalous and malicious events.

### Module 02: Network Reconnaissance & Penetration Testing Report
Located in `02-network-recon-vuln-assessment/`:
- A full technical penetration testing assessment conducted in accordance with the **Penetration Testing Execution Standard (PTES)**.
- Documented methodology covering passive OSINT, active host discovery (`nmap -sn -PE -PA80,443`), TCP SYN scanning (`nmap -sS`), service enumeration (`-sV -O`), and DNS AXFR zone transfer vulnerabilities against BIND 9.18.12.
- Vulnerability findings mapped against CVSS v3.0 metrics (including critical findings for vsftpd 2.3.4 backdoor CVE-2011-2523 and distccd command execution CVE-2004-2687).
- False positive analysis on Apache directory listing findings.

### Module 03: Hardened Flask REST API
Located in `03-flask-secure-api/`:
- Secure RESTful application designed around **STRIDE threat modeling** principles.
- Cryptographically sound authentication utilizing salted Bcrypt password hashing.
- Parameterized database operations preventing SQL injection vulnerabilities.
- Sliding-window rate limiting per client IP, constant-time secret comparison (`hmac.compare_digest`), HTTP security headers, and structured audit logging.

---

## STRIDE Threat Model & Defense Matrix

| STRIDE Threat Category | Target Surface | Engineering Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Authentication endpoints (`/login`) | Salted Bcrypt hashing with adaptive work factor, input length bounds |
| **Tampering** | Database persistence layer | Strictly parameterized SQL queries and schema input constraints |
| **Repudiation** | Sensitive admin operations | Structured immutable audit logs with epoch timestamps and client hashes |
| **Information Disclosure** | Application error handlers | Sanitized error responses with stack trace masking and header filtering |
| **Denial of Service** | Public API routes | Sliding-window IP rate limiting and HTTP body payload bounds |
| **Elevation of Privilege** | Administrative endpoints | Role-based middleware with constant-time token comparison |

---

## Setup & Execution

### 1. Security Automation & ML
```bash
cd 01-python-security-automation-ml
pip install -r requirements.txt

# Run multithreaded TCP port scanner
python port_scanner.py --target 127.0.0.1 --ports 1-1024

# Run ML threat detection pipeline (Log Inference)
python ml_threat_detector.py --input sample_logs.txt

# Run ML threat detection pipeline (Synthetic Benchmark)
python ml_threat_detector.py --benchmark

# Run IP threat intelligence (Mock mode)
python virustotal_check.py --mock 8.8.8.8 185.220.101.5
```

### 2. Network Reconnaissance Audit
The complete findings, raw scan output logs, and BIND configuration manifests are detailed in:
`02-network-recon-vuln-assessment/README.md`

### 3. Hardened Flask API
```bash
cd 03-flask-secure-api
pip install -r requirements.txt
python app.py
```

### 4. Automated Testing & Security Verification
```bash
# Run complete test suite (53 automated tests)
pytest -v

# Run Static Application Security Testing (SAST)
bandit -r 01-python-security-automation-ml 03-flask-secure-api
```

---

## Project Structure

```text
Cybersecurity-Automation-And-Intelligent-Threat-Detection/
├── .github/
│   ├── dependabot.yml
│   └── workflows/
│       ├── codeql.yml
│       └── security.yml
├── 01-python-security-automation-ml/
│   ├── .env.example
│   ├── .gitignore
│   ├── log_enricher.py
│   ├── ml_threat_detector.py
│   ├── port_scanner.py
│   ├── README.md
│   ├── requirements.txt
│   ├── sample_logs.txt
│   └── virustotal_check.py
├── 02-network-recon-vuln-assessment/
│   ├── configs/
│   ├── outputs/
│   ├── scope.md
│   └── README.md
├── 03-flask-secure-api/
│   ├── .env.example
│   ├── .gitignore
│   ├── app.py
│   ├── crypto.py
│   ├── README.md
│   └── requirements.txt
├── tests/
│   ├── __init__.py
│   ├── test_flask_api.py
│   ├── test_log_enricher.py
│   ├── test_ml_threat_detector.py
│   ├── test_port_scanner.py
│   └── test_virustotal_check.py
├── .gitignore
├── LICENSE
└── README.md
```

---

## License

Distributed under the [MIT License](LICENSE).
