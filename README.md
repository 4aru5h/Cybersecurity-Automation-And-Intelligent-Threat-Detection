# Cybersecurity Capstone

A collection of security projects covering automation, threat detection, lab penetration testing, and secure API development.

Built as a capstone project for computer engineering at MPSTME, NMIMS.

---

## Modules

- `01-python-security-automation-ml`: Multithreaded TCP port scanner, VirusTotal REST API integration, SOC log enricher, and ML anomaly detection (Isolation Forest and Random Forest).
- `02-network-recon-vuln-assessment`: Formal penetration test against an isolated host-only subnet (Kali Linux, BIND9 DNS, Metasploitable 2) with vulnerability findings and CVSS scoring.
- `03-flask-secure-api`: Hardened REST API designed around STRIDE threat modeling, utilizing Argon2/Bcrypt password hashing, parameterized queries, and CI/CD security workflows.

---

## Usage

### Security Automation & ML
```bash
cd 01-python-security-automation-ml
pip install -r requirements.txt
python port_scanner.py --target 127.0.0.1 --ports 1-1024
python ml_threat_detector.py --input sample_logs.txt
```

### Network Reconnaissance
The full report, methodology, and configuration logs are available in `02-network-recon-vuln-assessment/README.md`.

### Hardened Flask API
```bash
cd 03-flask-secure-api
pip install -r requirements.txt
python app.py
```

---

## License

MIT
