# Architecture, Threat Model & Project Structure

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



## Project Structure

```text
Cybersecurity-Automation-And-Intelligent-Threat-Detection/
â”œâ”€â”€ .github/
â”‚   â”œâ”€â”€ dependabot.yml
â”‚   â””â”€â”€ workflows/
â”‚       â”œâ”€â”€ codeql.yml
â”‚       â””â”€â”€ security.yml
â”œâ”€â”€ 01-python-security-automation-ml/
â”‚   â”œâ”€â”€ .env.example
â”‚   â”œâ”€â”€ .gitignore
â”‚   â”œâ”€â”€ log_enricher.py
â”‚   â”œâ”€â”€ ml_threat_detector.py
â”‚   â”œâ”€â”€ port_scanner.py
â”‚   â”œâ”€â”€ README.md
â”‚   â”œâ”€â”€ requirements.txt
â”‚   â”œâ”€â”€ sample_logs.txt
â”‚   â””â”€â”€ virustotal_check.py
â”œâ”€â”€ 02-network-recon-vuln-assessment/
â”‚   â”œâ”€â”€ configs/
â”‚   â”œâ”€â”€ outputs/
â”‚   â”œâ”€â”€ scope.md
â”‚   â””â”€â”€ README.md
â”œâ”€â”€ 03-flask-secure-api/
â”‚   â”œâ”€â”€ .env.example
â”‚   â”œâ”€â”€ .gitignore
â”‚   â”œâ”€â”€ app.py
â”‚   â”œâ”€â”€ crypto.py
â”‚   â”œâ”€â”€ README.md
â”‚   â””â”€â”€ requirements.txt
â”œâ”€â”€ tests/
â”‚   â”œâ”€â”€ __init__.py
â”‚   â”œâ”€â”€ test_flask_api.py
â”‚   â”œâ”€â”€ test_log_enricher.py
â”‚   â”œâ”€â”€ test_ml_threat_detector.py
â”‚   â”œâ”€â”€ test_port_scanner.py
â”‚   â””â”€â”€ test_virustotal_check.py
â”œâ”€â”€ .gitignore
â”œâ”€â”€ LICENSE
â””â”€â”€ README.md
```

---


