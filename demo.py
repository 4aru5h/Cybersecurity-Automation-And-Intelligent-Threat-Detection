#!/usr/bin/env python3
"""
Live End-to-End Demonstration Script for Cybersecurity Suite
Demonstrates:
  1. Multithreaded TCP Port Scanner with banner grabbing
  2. Dual-model Machine Learning Threat Detector on real logs
  3. Hardened Flask REST API (STRIDE defenses & Audit logging)
"""

import os
import socket
import sys
import threading
import time

# Ensure submodules are in python path
sys.path.insert(0, os.path.abspath("01-python-security-automation-ml"))
sys.path.insert(0, os.path.abspath("03-flask-secure-api"))

from port_scanner import scan_target, format_scan_table
from ml_threat_detector import run_log_inference_mode
from app import app, init_db


def run_demo():
    print("=" * 80)
    print("       CYBERSECURITY CAPSTONE SUITE: LIVE END-TO-END DEMO")
    print("=" * 80)

    # -------------------------------------------------------------
    # DEMO 1: Port Scanner with Banner Grabbing
    # -------------------------------------------------------------
    print("\n[DEMO 1] HIGH-SPEED MULTITHREADED TCP PORT SCANNER")
    print("-" * 80)
    print("[*] Starting an ephemeral mock FTP service on localhost port 2121...")

    srv_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv_sock.bind(("127.0.0.1", 2121))
    srv_sock.listen(5)

    def handle_clients():
        while True:
            try:
                conn, _ = srv_sock.accept()
                conn.sendall(b"220 ProFTPD 1.3.5 Server (Lab Demo Ready)\r\n")
                try:
                    conn.recv(1024)
                except Exception:
                    pass
                conn.close()
            except OSError:
                break

    srv_thread = threading.Thread(target=handle_clients, daemon=True)
    srv_thread.start()
    time.sleep(0.1)

    print("[*] Scanning ports [80, 443, 2121, 8080] on 127.0.0.1 using ThreadPoolExecutor...")
    target_ip, open_ports = scan_target("127.0.0.1", [80, 443, 2121, 8080], timeout=0.5)
    print(format_scan_table("127.0.0.1", target_ip, open_ports))

    srv_sock.close()

    # -------------------------------------------------------------
    # DEMO 2: AI Machine Learning Threat Detector on Raw Logs
    # -------------------------------------------------------------
    print("[DEMO 2] AI MACHINE LEARNING THREAT DETECTION (RAW LOGS)")
    print("-" * 80)
    log_path = os.path.join("01-python-security-automation-ml", "sample_logs.txt")
    print(f"[*] Ingesting and parsing log records from: {log_path}\n")

    run_log_inference_mode(log_path)

    # -------------------------------------------------------------
    # DEMO 3: Hardened Flask API & STRIDE Security Controls
    # -------------------------------------------------------------
    print("\n[DEMO 3] HARDENED FLASK REST API (STRIDE SECURITY & AUDIT TRAIL)")
    print("-" * 80)
    demo_db = "demo_ephemeral.db"
    os.environ["DATABASE_PATH"] = demo_db
    os.environ["ADMIN_API_KEY"] = "super-secret-admin-token-2026"

    init_db(demo_db)
    client = app.test_client()

    print("[*] Testing API Endpoints & Security Controls:")

    # 1. Register User
    r1 = client.post("/register", json={"username": "agent_smith", "password": "StrongPassword123!"})
    print(f"  1. Register User ('agent_smith')       -> HTTP {r1.status_code}: {r1.get_json()['message']}")

    # 2. Duplicate Registration Attempt
    r2 = client.post("/register", json={"username": "agent_smith", "password": "StrongPassword123!"})
    print(f"  2. Duplicate Registration Defense      -> HTTP {r2.status_code}: {r2.get_json()['error']}")

    # 3. Invalid Login (Wrong Password)
    r3 = client.post("/login", json={"username": "agent_smith", "password": "WrongPassword!"})
    print(f"  3. Brute-Force Password Defense        -> HTTP {r3.status_code}: {r3.get_json()['error']}")

    # 4. Valid Login
    r4 = client.post("/login", json={"username": "agent_smith", "password": "StrongPassword123!"})
    print(f"  4. Successful Bcrypt Authentication    -> HTTP {r4.status_code}: {r4.get_json()['message']}")

    # 5. Unauthorized Admin Access
    r5 = client.get("/admin")
    print(f"  5. Unauthorized Admin Probe            -> HTTP {r5.status_code}: {r5.get_json()['error']}")

    # 6. Forged Bearer Token (Timing Attack Mitigated)
    r6 = client.get("/admin", headers={"Authorization": "Bearer forged-fake-token-xyz"})
    print(f"  6. Forged Bearer Token Defense         -> HTTP {r6.status_code}: {r6.get_json()['error']}")

    # 7. Authorized Admin Access
    r7 = client.get("/admin", headers={"Authorization": "Bearer super-secret-admin-token-2026"})
    print(f"  7. Authorized Admin Access             -> HTTP {r7.status_code}: {r7.get_json()['data']}")

    # 8. Check Security Headers
    print(f"  8. Browser Security Headers Attached   -> X-Frame-Options: {r7.headers.get('X-Frame-Options')}, "
          f"X-Content-Type-Options: {r7.headers.get('X-Content-Type-Options')}")

    # 9. Review Immutable Audit Trail
    r8 = client.get("/admin/audit-logs", headers={"Authorization": "Bearer super-secret-admin-token-2026"})
    logs = r8.get_json().get("audit_logs", [])
    print(f"\n[+] Immutable Security Audit Trail ({len(logs)} events logged in SQLite):")
    for log in logs[:6]:
        ts = log["timestamp"][:19].replace("T", " ")
        act = log["action"]
        st = log["status"]
        user = log["user_identifier"]
        print(f"    [{ts}] Action: {act:<14} Status: {st:<18} Target: {user}")

    # Cleanup demo db
    if os.path.exists(demo_db):
        try:
            os.remove(demo_db)
        except OSError:
            pass

    print("\n" + "=" * 80)
    print("      LIVE DEMONSTRATION COMPLETE: ALL SYSTEMS FULLY OPERATIONAL")
    print("=" * 80)


if __name__ == "__main__":
    run_demo()
