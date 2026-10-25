# Cybersecurity Capstone: Threat Detection, Security Automation & Hardened Infrastructure

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
        | - Dual ML Models  |                                                   | - Argon2id Auth   |
        +-------------------+                                                   +-------------------+
```

---

## Modules Summary

### Module 01: Python Security Automation & Machine Learning
Located in `01-python-security-automation-ml/`:
- **Multithreaded Port Scanner (`port_scanner.py`):** High-speed TCP port scanner with customizable thread pools, socket timeout controls, service banner extraction, and formatted reporting.
- **Log Enrichment Engine (`log_enricher.py`):** Parses authentication and web access logs, extracts public IPv4 indicators, and flags anomaly thresholds.
- **Threat Intelligence Integrator (`virustotal_check.py`):** Interfaces with the VirusTotal REST API v3 to enrich file hashes and IP indicators with community threat reputation scores.
- **Dual-Model ML Threat Detector (`ml_threat_detector.py`):**
  - Unsupervised Anomaly Detection: `IsolationForest` to discover anomalous request patterns and volume deviations in unlabelled access logs.
  - Supervised Threat Classifier: `RandomForestClassifier` trained to differentiate benign traffic from brute-force authentication and port scanning attempts.

### Module 02: Network Reconnaissance & Penetration Testing Report
Located in `02-network-recon-vuln-assessment/`:
- A full technical penetration testing assessment conducted in accordance with the **Penetration Testing Execution Standard (PTES)**.
- Documented methodology covering passive OSINT, active host discovery (`nmap -sn -PE -PA80,443`), TCP SYN scanning (`nmap -sS`), service enumeration (`-sV -O`), and DNS AXFR zone transfer vulnerabilities against BIND 9.18.12.
- Vulnerability findings mapped against CVSS v3.0 metrics (including critical findings for vsftpd 2.3.4 backdoor CVE-2011-2523 and distccd command execution CVE-2004-2687).
- False positive analysis on Apache directory listing findings.

### Module 03: Hardened Flask REST API
Located in `03-flask-secure-api/`:
- Secure RESTful application designed around **STRIDE threat modeling** principles.
- Cryptographically sound authentication utilizing salted Argon2 and Bcrypt password hashing.
- Parameterized database operations preventing SQL injection vulnerabilities.
- Enforced security headers, rate limiting, and role-based access control (RBAC).

---

## STRIDE Threat Model & Defense Matrix

| STRIDE Threat Category | Target Surface | Engineering Mitigation |
| :--- | :--- | :--- |
| **Spoofing** | Authentication endpoints (`/login`) | Salted Argon2id hashing, secure JWT claims with brief validity |
| **Tampering** | Database persistence layer | Strictly parameterized SQL queries and schema input constraints |
| **Repudiation** | Sensitive admin operations | Structured immutable audit logs with epoch timestamps and client hashes |
| **Information Disclosure** | Application error handlers | Sanitized error responses with stack trace masking and header filtering |
| **Denial of Service** | Public API routes | Token-bucket rate limiting and HTTP body payload bounds |
| **Elevation of Privilege** | Administrative endpoints | Role-based middleware verifying claims prior to route execution |

---

## Setup & Execution

### 1. Security Automation & ML
```bash
cd 01-python-security-automation-ml
pip install -r requirements.txt

# Run multithreaded TCP port scanner
python port_scanner.py --target 127.0.0.1 --ports 1-1024

# Run ML threat detection pipeline
python ml_threat_detector.py --input sample_logs.txt
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

---

## Project Structure

```text
Cybersecurity-Automation-And-Intelligent-Threat-Detection/
├── 01-python-security-automation-ml/
│   ├── port_scanner.py
│   ├── log_enricher.py
│   ├── virustotal_check.py
│   ├── ml_threat_detector.py
│   ├── sample_logs.txt
│   └── requirements.txt
├── 02-network-recon-vuln-assessment/
│   ├── configs/
│   ├── outputs/
│   ├── scope.md
│   └── README.md
├── 03-flask-secure-api/
│   ├── app.py
│   ├── crypto.py
│   └── requirements.txt
├── LICENSE
└── README.md
```

---

## License

Distributed under the [MIT License](LICENSE).
