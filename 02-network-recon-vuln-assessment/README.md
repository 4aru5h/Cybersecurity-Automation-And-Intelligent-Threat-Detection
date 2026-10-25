# network-recon-vuln-assessment
# Penetration Test Report: Network Reconnaissance and Vulnerability Assessment

## Lab Environment Notes
* **Attacker System:** Kali Linux 2024.1 (`192.168.56.10/24`)
* **DNS Server VM:** Ubuntu Server 22.04 LTS running BIND9 (`192.168.56.15/24`)
* **Vulnerable Target VM:** Metasploitable 2 (`192.168.56.20/24`)
* **Network Segment:** `192.168.56.0/24` (Isolated Host-Only Virtual Subnet)

---

## 1. Executive Summary
An authorized security assessment was conducted against the target lab network segment (`192.168.56.0/24`). The evaluation identified multiple critical security risks on target host `192.168.56.20`, including legacy unpatched services containing remote code execution vulnerabilities (CVSS 9.8) and an insecurely configured local DNS server (`192.168.56.15`) permitting unauthorized zone transfers (AXFR). Immediate remediation is required to isolate vulnerable services, patch legacy software components, and restrict DNS transfer access control lists.

---

## 2. Scope and Rules of Engagement

### Authorized Target Range
* **Subnet:** `192.168.56.0/24`
* **Target Assets:** `192.168.56.15` (DNS Server), `192.168.56.20` (Metasploitable 2 Target)

### In-Scope Activities
* Passive OSINT reconnaissance.
* Active ICMP/TCP host discovery.
* TCP SYN port scanning, service version detection (`-sV`), and OS fingerprinting (`-O`).
* Authoritative DNS record querying and zone transfer attempts (AXFR).
* Automated vulnerability scanning using Nessus.

### Out-of-Scope Activities
* Active exploitation, execution of Proof-of-Concept payloads, or shell interaction.
* Post-exploitation activities (privilege escalation, pivoting, data exfiltration).
* Denial of Service (DoS) attacks or network stress testing.
* Any scanning directed at IP space outside `192.168.56.0/24`.

### Rules of Engagement
* **Testing Window:** Monday to Friday, 09:00 to 17:00 UTC.
* **Rate Limits:** Maximum scanning throughput capped at 100 packets per second (`--max-rate 100`).
* **Emergency Contact:** Primary Security Lead (`security-lead@lab.local` / `+1-555-019-2831`).

---

## 3. Methodology
This assessment followed the **Penetration Testing Execution Standard (PTES)** across three core phases:

1. **Pre-Engagement:** Standardized scope boundaries, defined target ranges, and established rules of engagement.
2. **Intelligence Gathering:**
   * **Passive OSINT:** Gathered public DNS records and index data to demonstrate non-intrusive reconnaissance.
   * **Active Host Discovery:** Executed Nmap ping sweeps to identify live systems prior to full port scanning.
   * **Port Scanning & Service Enumeration:** Performed TCP SYN scanning, service version detection, and OS fingerprinting.
   * **DNS Enumeration:** Interrogated the local authoritative BIND9 DNS server for records and tested zone transfer vulnerabilities.
3. **Vulnerability Analysis:** Conducted automated vulnerability scans using Nessus to correlate active services with known CVE databases.

---

## 4. Passive OSINT Findings

Passive OSINT was demonstrated against public domains and search indexing platforms without transmitting packets to the target lab network.

| Intelligence Source | Query / Target | Result Data | Risk Level | Attacker Inference & Operational Impact |
| :--- | :--- | :--- | :--- | :--- |
| **Passive DNS** | `example.com` (A/MX/NS) | `A: 93.184.215.14`<br>`MX: mail.example.com`<br>`NS: a.iana-servers.net` | **Low** | Maps primary web host provider and public mail exchange entry point. Identifies infrastructure boundaries. |
| **Passive DNS** | `example.com` (TXT) | `v=spf1 include:_spf.google.com ~all` | **Medium** | Reveals third-party mail vendor (Google Workspace) and soft-fail SPF policy (`~all`), indicating potential email spoofing risk. |
| **Shodan Query** | `product:Apache country:US` | `Apache/2.4.41 (Ubuntu)` on Port 80 | **High** | Discloses exact web server daemon and underlying OS version, enabling target lookup for specific unpatched vulnerabilities. |

---

## 5. Active Reconnaissance & Technical Findings

### Active Host Discovery
Executed Nmap ping sweep across `192.168.56.0/24`:
```bash
nmap -sn -PE -PA80,443 -PP 192.168.56.0/24 -oN outputs/ping_sweep.nmap
```

* **Flag Justifications:**
  * `-sn`: Host discovery only; disables port scanning.
  * `-PE`: Sends ICMP Echo Request probes.
  * `-PA80,443`: Sends TCP ACK probes to ports 80 and 443 to bypass basic ICMP filters.
  * `-PP`: Sends ICMP Timestamp Request probes for extra discovery coverage.
  * `-oN outputs/ping_sweep.nmap`: Outputs findings in standard Nmap text format.

* **Discovered Live Hosts:**
  * `192.168.56.10` (Attacker Host - Kali Linux)
  * `192.168.56.15` (DNS Server - Ubuntu BIND9)
  * `192.168.56.20` (Target Host - Metasploitable 2)

* **PTES Rationale:** Host discovery precedes port scanning to prevent wasting bandwidth scanning dead IP addresses across large subnets, minimizing network noise and reducing execution time.

---

### Port Scanning & Service Enumeration
Executed TCP SYN scan across ports 1–1024, followed by service detection and OS fingerprinting:
```bash
# TCP SYN Port Scan (Ports 1-1024)
nmap -sS -p 1-1024 192.168.56.20 -oN outputs/syn_scan.nmap

# Service Version Detection & OS Fingerprinting
nmap -sS -sV -O -p 21,22,23,25,53,80 192.168.56.20 -oN outputs/service_os_scan.nmap
```

#### TCP SYN vs. TCP Connect Scan (Packet-Level Technical Comparison)
* **TCP Connect Scan (`-sT`):** Completes the full 3-way handshake (`SYN` -> `SYN-ACK` -> `ACK`). The operating system network stack creates a complete connection before closing it with `FIN` or `RST`. This invokes standard OS socket connection calls (`accept()`), logging the connection in application logs.
* **TCP SYN Scan (`-sS`):** Performs a half-open handshake. The attacker sends a `SYN` packet; the target responds with `SYN-ACK`. The attacker immediately terminates the connection by sending a `RST` packet instead of completing the handshake with an `ACK`. Because the 3-way handshake never completes, application layers do not log the connection, making SYN scans stealthier against standard application logging.

#### Service Enumeration Results

| Host | Port | State | Service | Version | OS |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `192.168.56.15` | `53/TCP` | Open | domain | BIND 9.18.12 | Linux 5.x / Ubuntu |
| `192.168.56.20` | `21/TCP` | Open | ftp | vsftpd 2.3.4 | Linux 2.6.x (Ubuntu) |
| `192.168.56.20` | `22/TCP` | Open | ssh | OpenSSH 4.7p1 (Protocol 2.0) | Linux 2.6.x (Ubuntu) |
| `192.168.56.20` | `23/TCP` | Open | telnet | Linux telnetd | Linux 2.6.x (Ubuntu) |
| `192.168.56.20` | `25/TCP` | Open | smtp | Postfix smtpd | Linux 2.6.x (Ubuntu) |
| `192.168.56.20` | `80/TCP` | Open | http | Apache httpd 2.2.8 ((Ubuntu)) | Linux 2.6.x (Ubuntu) |

---

### Authoritative DNS Enumeration & Configuration Findings

#### BIND9 Server Excerpt (`/etc/bind/named.conf.local`)
```bind
zone "lab.local" {
    type master;
    file "/etc/bind/db.lab.local";
    allow-transfer { any; };
};
```

#### BIND9 Zone File (`/etc/bind/db.lab.local`)
```text
$TTL    604800
@       IN      SOA     ns1.lab.local. admin.lab.local. (
                              2026081501 ; Serial
                                  604800 ; Refresh
                                   86400 ; Retry
                                 2419200 ; Expire
                                  604800 ) ; Negative Cache TTL
; Name Servers
@       IN      NS      ns1.lab.local.

; A Records
ns1     IN      A       192.168.56.15
web     IN      A       192.168.56.20
target  IN      A       192.168.56.20

; MX Record
@       IN      MX  10  mail.lab.local.
mail    IN      A       192.168.56.20

; CNAME Record
www     IN      CNAME   web.lab.local.

; TXT Record
@       IN      TXT     "v=spf1 mx a -all"
```

#### DNS Enumeration Output Summary
* **Standard DNS Query (`dig ANY lab.local @192.168.56.15`):** Returned valid `SOA`, `NS`, `MX`, and `TXT` records for the zone.
* **Zone Transfer Test (`dig axfr @192.168.56.15 lab.local`):** Succeeded completely, dumping all 10 zone records.
* **Security Impact of AXFR Failure:** Allowing unrestricted AXFR transfers allows unauthenticated remote attackers to obtain the full DNS zone file. This exposes internal IP schemes, internal hostnames, and hidden infrastructure without requiring manual brute-forcing.

---

## 6. Automated Vulnerability Scanning Findings

### Detailed Vulnerability Analysis

#### 1. VSFTPD v2.3.4 Backdoor Command Execution
* **CVE Identifier:** CVE-2011-2523
* **CVSS v3.0 Base Score:** 9.8 (Critical)
* **CVSS Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **Affected Asset:** `192.168.56.20:21` (FTP)
* **Remediation Recommendation:** The installed version of vsftpd contains a known backdoor triggered by submitting a `:)` sequence in the username field, opening a listening shell on port 6200. Immediately upgrade vsftpd to version 3.0.5 or higher, or replace vsftpd with an authenticated, secure SFTP service running over SSH.

#### 2. OpenSSL Heartbleed Information Disclosure
* **CVE Identifier:** CVE-2014-0160
* **CVSS v3.0 Base Score:** 7.5 (High)
* **CVSS Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N`
* **Affected Asset:** `192.168.56.20:443` (HTTPS)
* **Remediation Recommendation:** The OpenSSL service handles TLS heartbeat extension packets improperly, allowing remote attackers to read up to 64KB of memory per request. This exposes process memory, session tokens, and private keys. Recompile OpenSSL with `-DOPENSSL_NO_HEARTBEAT` or upgrade OpenSSL to version 1.0.1g or higher, and revoke/reissue all SSL/TLS certificates.

#### 3. Distcc Daemon Arbitrary Command Execution
* **CVE Identifier:** CVE-2004-2687
* **CVSS v3.0 Base Score:** 9.8 (Critical)
* **CVSS Vector String:** `CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
* **Affected Asset:** `192.168.56.20:3632` (distccd)
* **Remediation Recommendation:** The distcc compilation daemon exposes an unauthenticated service that accepts compilation requests containing embedded system commands. Restrict distccd access control lists (`--allow`) to trusted IP addresses, or disable the daemon completely if distributed compilation is not required.

---

### False Positive Identification and Analysis

* **Flagged Finding:** *Apache HTTP Server Directory Listing Enabled*
* **Scanner Severity:** Medium (Nessus Plugin ID 10719)
* **Analysis & Verification:** The scanner flagged port 80/TCP because directory browsing was enabled on the root web directory. Manual inspection confirmed that the index lists standard public documentation files without exposed configuration files, credentials, or internal source code.
* **Conclusion:** This finding is classified as a **false positive** regarding high-severity risk impact. While directory browsing is enabled, the absence of sensitive data lowers the actual operational risk to Informational.

---

## 7. Master Findings Table

| Vulnerability Title | CVE | CVSS v3.0 | Severity | Affected Asset | Remediation Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **VSFTPD Backdoor RCE** | CVE-2011-2523 | 9.8 | Critical | `192.168.56.20:21` | Upgrade vsftpd to version >= 3.0.5 or replace with SFTP. |
| **Distcc Daemon Exec** | CVE-2004-2687 | 9.8 | Critical | `192.168.56.20:3632` | Restrict distccd access control list or disable daemon. |
| **OpenSSL Heartbleed** | CVE-2014-0160 | 7.5 | High | `192.168.56.20:443` | Upgrade OpenSSL to version >= 1.0.1g; revoke and reissue SSL keys. |
| **Unrestricted DNS AXFR** | N/A | 7.5 | High | `192.168.56.15:53` | Update BIND `allow-transfer` ACL to restrict zone transfers. |
| **Telnet Plaintext Auth** | CVE-1999-0619 | 5.3 | Medium | `192.168.56.20:23` | Disable Telnet service and enforce SSH for remote administration. |

---

## 8. Risk Heat Map Analysis

```text
               IMPACT
           Low   Med   High
        ┌─────┬─────┬──────┐
   High │     │ Tel │ RCE  │  <-- VSFTPD / Distcc / AXFR
L       ├─────┼─────┼──────┤
I  Med  │ FP  │     │ Hbl  │  <-- Heartbleed
K       ├─────┼─────┼──────┤
   Low  │     │     │      │
        └─────┴─────┴──────┘
```

* **High Likelihood / High Impact (Critical Quadrant):** `VSFTPD Backdoor (CVE-2011-2523)` and `Distcc Daemon (CVE-2004-2687)`. Exploitation requires zero authentication and provides immediate root privilege.
* **High Likelihood / High Impact (High Quadrant):** `Unrestricted DNS AXFR`. Easily executed via basic DNS clients (`dig`); exposes full internal target network topology.
* **Medium Likelihood / High Impact (High Quadrant):** `OpenSSL Heartbleed (CVE-2014-0160)`. Requires HTTPS traffic extraction, but risks exposing system memory and private keys.
* **High Likelihood / Medium Impact (Medium Quadrant):** `Telnet Plaintext Auth`. Credentials travel unencrypted and can be captured using local network sniffing.
* **Medium Likelihood / Low Impact (Low Quadrant):** `Directory Listing Enabled`. Minimal informational exposure (verified false positive for sensitive disclosure).

---

## 9. Remediation Priority List (CVSS Score Ranked)

1. **Priority 1: VSFTPD Backdoor (CVE-2011-2523) — CVSS 9.8**
   * Replace vsftpd v2.3.4 with a supported release or replace with SFTP over SSH.
2. **Priority 2: Distcc Daemon Remote Execution (CVE-2004-2687) — CVSS 9.8**
   * Block port 3632 at firewall level or restrict distccd allowed subnet directives.
3. **Priority 3: DNS Zone Transfer Misconfiguration — CVSS 7.5**
   * Update `/etc/bind/named.conf.local` to set `allow-transfer { none; };` or specify authorized secondary DNS IP addresses only.
4. **Priority 4: OpenSSL Heartbleed Vulnerability (CVE-2014-0160) — CVSS 7.5**
   * Patch OpenSSL libraries to version 1.0.1g or higher and regenerate internal server SSL certificates.
5. **Priority 5: Unencrypted Telnet Daemon (CVE-1999-0619) — CVSS 5.3**
   * Stop and disable `telnetd`; enforce SSH for all remote management.
