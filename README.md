# Cybersecurity Capstone: Automated Threat Detection, Network Reconnaissance & Secure SDLC

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python)](https://www.python.org/)
[![Security: STRIDE Modeled](https://img.shields.io/badge/Security-STRIDE%20Modeled-green.svg)](03-flask-secure-api/README.md)
[![Status: Capstone Complete](https://img.shields.io/badge/Status-Capstone%20Production-success.svg)]()

> **Author:** Aarush Sharma  
> **Affiliation:** Mukesh Patel School of Technology Management & Engineering (MPSTME, NMIMS)  
> **Discipline:** Computer Engineering // Cybersecurity

---

## 🎯 Executive Overview

This repository represents the unified capstone engineering suite integrating three critical pillars of modern defensive and offensive cybersecurity:

1. **Security Operations & Threat Intelligence Automation** — Multithreaded reconnaissance, threat intelligence API enrichment, and dual-model unsupervised machine learning for anomaly detection.
2. **Offensive Security & Network Vulnerability Assessment** — Controlled penetration testing of an isolated lab network (Kali Linux, BIND9 DNS, Metasploitable 2) with formal CVSS scoring and remediation strategies.
3. **Application Security & Hardened DevSecOps SDLC** — Microservices REST API built from the ground up under the STRIDE threat model, incorporating cryptographic hashing, parameterized persistence, and automated CI/CD security scanning.

---

## 🏗️ Unified Architecture

```text
                               +--------------------------------------------+
                               |        Target Lab Network / Subnet         |
                               | (Kali Linux | BIND9 DNS | Metasploitable 2)|
                               +---------------------+----------------------+
                                                     |
                                   (Reconnaissance & Vulnerability Audit)
                                                     v
                               +--------------------------------------------+
                               | Module 02: Network Recon & Pentest Report  |
                               |  - Port Scans, DNS Misconfigs, CVSS Triage |
                               +---------------------+----------------------+
                                                     |
                                            (Telemetry & Logs)
                                                     v
+----------------------------------------------------+----------------------------------------------------+
|                               Module 01: Python Security Automation & ML                                |
|  +-----------------------+      +---------------------------+      +---------------------------------+  |
|  | Multi-threaded Scanner| ---> | Threat Intel (VirusTotal) | ---> | ML Detector (Random / Isolation)|  |
|  +-----------------------+      +---------------------------+      +---------------------------------+  |
+----------------------------------------------------+----------------------------------------------------+
                                                     |
                                   (Remediation & Secure Architecture)
                                                     v
+----------------------------------------------------+----------------------------------------------------+
|                                Module 03: Hardened Flask API & Secure SDLC                              |
|  +-----------------------+      +---------------------------+      +---------------------------------+  |
|  | STRIDE Threat Model   | ---> | Argon2/Bcrypt Cryptography| ---> | Automated CI/CD Security Checks |  |
|  +-----------------------+      +---------------------------+      +---------------------------------+  |
+---------------------------------------------------------------------------------------------------------+
```

---

## 📂 Repository Module Structure

```text
Cybersecurity-Automation-And-Intelligent-Threat-Detection/
├── 01-python-security-automation-ml/      # SOC Automation & Machine Learning Threat Detection
│   ├── log_enricher.py                    # Real-time log parser & threat intel aggregator
│   ├── ml_threat_detector.py              # Dual ML engine (Isolation Forest & Random Forest)
│   ├── port_scanner.py                    # High-speed multithreaded socket port scanner
│   ├── virustotal_check.py                # VirusTotal REST v3 integration
│   ├── sample_logs.txt                    # Standardized network telemetry dataset
│   └── requirements.txt                   # Scikit-learn, Pandas, Requests, etc.
│
├── 02-network-recon-vuln-assessment/      # Offensive Security & Formal Pentest Audit
│   ├── scope.md                           # Rules of Engagement (RoE) and asset boundaries
│   ├── configs/                           # DNS (BIND9), service, and network configurations
│   ├── outputs/                           # Raw Nmap, Nikto, and exploit triage outputs
│   └── README.md                          # Full 14KB Penetration Test Report & CVSS matrix
│
├── 03-flask-secure-api/                   # DevSecOps & Secure Microservice Architecture
│   ├── app.py                             # Hardened Flask REST endpoints with parameterized SQL
│   ├── crypto.py                          # Cryptographic token signing and salted password hashing
│   ├── .github/workflows/                 # Automated SAST / security linting pipeline
│   └── README.md                          # Comprehensive STRIDE Threat Model documentation
│
├── .gitignore                             # Production Git exclusion rules
├── LICENSE                                # MIT Open Source License
└── README.md                              # Master Capstone Portfolio Guide
```

---

## 🚀 Module Deep Dives & Quickstart

### Module 01: Python Security Automation & ML Threat Detection
- **Key Capabilities:**
  - **Multithreaded Port Scanner:** Standard socket library scanner with banner grabbing and connection timeout handling.
  - **Threat Intelligence Enrichment:** Parses raw IP/domain indicators and queries the VirusTotal API for threat scores.
  - **Unsupervised ML Detection:** Employs `IsolationForest` for zero-day anomaly detection and `RandomForestClassifier` for signature classification.
- **Run Module 01:**
  ```bash
  cd 01-python-security-automation-ml
  pip install -r requirements.txt
  python port_scanner.py --target 127.0.0.1 --ports 1-1024
  python ml_threat_detector.py --input sample_logs.txt
  ```

---

### Module 02: Network Reconnaissance & Vulnerability Assessment
- **Key Capabilities:**
  - **Target Environment:** Isolated Virtual Subnet (`192.168.56.0/24`) comprising Kali Linux 2024.1, Ubuntu Server 22.04 with BIND9 DNS, and Metasploitable 2.
  - **Findings:** Documented DNS zone transfers (`AXFR`), unpatched daemon exploits, privilege escalation paths, and comprehensive CVSS v3.1 impact matrices.
  - Detailed findings, evidence logs, and executive mitigation plans are documented in [02-network-recon-vuln-assessment/README.md](02-network-recon-vuln-assessment/README.md).

---

### Module 03: Hardened Flask API & DevSecOps SDLC
- **Key Capabilities:**
  - **STRIDE Threat Modeling:** Explicitly maps Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, and Elevation of Privilege against REST endpoints.
  - **Cryptographic Safeguards:** Strong hashing algorithms (`argon2id` / `bcrypt`), salted token signatures, and rate limiting.
  - **Defensive Persistence:** Strict parameterized query layers to eliminate SQL Injection (CWE-89).
- **Run Module 03:**
  ```bash
  cd 03-flask-secure-api
  pip install -r requirements.txt
  python app.py
  ```

---

## 🛡️ STRIDE Threat Model Summary (Module 03)

| STRIDE Category | Vector Identified | Engineering Mitigation Implemented |
| :--- | :--- | :--- |
| **Spoofing** | Credential stuffing & token forgery | Salted Argon2id hashing & short-lived signed JWTs |
| **Tampering** | Query parameter payload manipulation | Parameterized SQL queries & strict input schema validation |
| **Repudiation** | Untracked privileged actions | Structured audit logging with immutable timestamps |
| **Information Disclosure** | Verbose database error exceptions | Generic error handlers & strict secret environment isolation |
| **Denial of Service** | Endpoint flooding & connection starvation | IP-based request rate limiting & payload size capping |
| **Elevation of Privilege** | Horizontal / vertical role tampering | Role-Based Access Control (RBAC) middleware checks |

---

## 📜 License
Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for full details.
