# Cybersecurity Automation & Threat Detection

A security engineering project built for my Cybersecurity and Ethical Hacking with Applied AI course from iHub DivyaSampark, IIT Roorkee.

It brings together automated reconnaissance tooling, machine learning for log anomaly detection, a PTES-compliant penetration testing lab audit, and a hardened Flask REST API.

---

## What's Inside

- **01. Security Automation & ML (`01-python-security-automation-ml/`):**
  - High-speed multithreaded TCP port scanner with socket timeout handling.
  - Public IP log enrichment via `ipaddress` and RFC-compliant geo-resolution.
  - Threat intelligence enrichment with the VirusTotal API v3 (includes mock mode for offline testing).
  - Anomaly detection comparing `RandomForestClassifier` and unsupervised `IsolationForest` on log features.

- **02. Network Reconnaissance & Penetration Testing (`02-network-recon-vuln-assessment/`):**
  - Technical audit of an isolated lab network (`192.168.56.0/24`) following the Penetration Testing Execution Standard (PTES).
  - Documented passive OSINT, active Nmap discovery/SYN scanning, BIND 9 DNS zone transfer checks, and vulnerability analysis against known CVEs.

- **03. Hardened Flask API (`03-flask-secure-api/`):**
  - REST service designed around STRIDE threat modeling.
  - Bcrypt password hashing with constant-time token verification (`hmac.compare_digest`).
  - Parameterized queries to prevent SQL injection, sliding-window rate limiting, and sanitized error responses.

For the full STRIDE threat matrix, network diagram, and complete file tree, see [docs/architecture.md](docs/architecture.md).

---

## Setup and Quickstart

```bash
# 1. Security Automation & ML
cd 01-python-security-automation-ml
pip install -r requirements.txt

# Port scan local or target host
python port_scanner.py --target 127.0.0.1 --ports 1-1024

# Threat detection on sample logs
python ml_threat_detector.py --input sample_logs.txt

# Run IP threat intelligence (offline mock mode)
python virustotal_check.py --mock 8.8.8.8 185.220.101.5

# 2. Hardened Flask API
cd ../03-flask-secure-api
pip install -r requirements.txt
python app.py
```

---

## Verification & Tests

```bash
# Run the test suite (53 automated tests)
pytest -v

# Run Static Application Security Testing (SAST)
bandit -r 01-python-security-automation-ml 03-flask-secure-api
```

---

## License

Distributed under the [MIT License](LICENSE).
