# Pre-Engagement Scope Document

## Lab Infrastructure Overview
* **Attacker Host:** Kali Linux 2024.1 (`192.168.56.10/24`)
* **Authoritative DNS Server:** Ubuntu Server 22.04 LTS with BIND9 (`192.168.56.15/24`)
* **Vulnerable Target System:** Metasploitable 2 (`192.168.56.20/24`)

---

## 1. Target Scope Definition
* **Authorized Target Subnet:** `192.168.56.0/24`
* **Target Assets:** `192.168.56.15` (DNS Server), `192.168.56.20` (Vulnerable Application Server)
* **Environment Type:** Isolated Local Virtual Network (Host-Only)

---

## 2. In-Scope Techniques
The following security assessment activities are explicitly authorized:
* **Passive OSINT:** Public domain reconnaissance, passive DNS query collection, and technology search engine queries (Shodan/Censys) against designated public assets for methodology demonstration.
* **Active Host Discovery:** ICMP and TCP ping sweeps across `192.168.56.0/24`.
* **Port Scanning & Service Enumeration:** TCP SYN (half-open) scans, TCP connect scans, service version detection (`-sV`), and OS fingerprinting (`-O`).
* **DNS Enumeration:** Direct DNS record queries (A, MX, NS, TXT, CNAME), reverse lookup checks, and zone transfer requests (AXFR) against the local DNS server (`192.168.56.15`).
* **Automated Vulnerability Scanning:** Host discovery and vulnerability scanning using Nessus or OpenVAS against live hosts inside `192.168.56.0/24`.

---

## 3. Out-of-Scope Activities
The following activities are strictly prohibited:
* **Exploitation & Post-Exploitation:** Running active exploit payloads, shell acquisition, privilege escalation, persistence mechanisms, or lateral movement.
* **Out-of-Bounds Targets:** Any network probe, scan, or packet generation directed at IP addresses outside `192.168.56.0/24`.
* **Disruptive Testing:** Denial of Service (DoS/DDoS) stress testing, network flooding, or brute-force password spraying.

---

## 4. Rules of Engagement (RoE)
* **Authorized Testing Window:** Monday through Friday, 09:00 to 17:00 UTC.
* **Scan Rate Constraints:** Active network probes capped at 100 packets per second (`--max-rate 100`) to avoid network stack saturation.
* **Emergency Escalation Contact:** Primary Security Lead (`security-lead@lab.local` / `+1-555-019-2831`).
* **Disruption Protocol:** If any host experiences instability or service degradation, scanning activities must be suspended immediately and reported to the primary contact.