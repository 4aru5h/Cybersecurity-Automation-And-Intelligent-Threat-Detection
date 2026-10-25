#!/usr/bin/env python3
"""
Multithreaded TCP Port Scanner with Banner Grabbing
Standard library implementation (no external scanner binaries).
"""

import argparse
import socket
import threading
from typing import List, Tuple

# Thread lock to synchronize safe writes to the shared results list across concurrent threads
print_lock = threading.Lock()
open_ports: List[Tuple[int, str, str]] = []


def grab_banner(target_ip: str, port: int, timeout: float) -> str:
    """Attempts to retrieve service banner from an open port."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((target_ip, port))
            # Send generic probe to elicit a server response header/banner
            s.sendall(b"\r\n")
            # Inline Comment 3: Banner Decoding
            # Decoding uses UTF-8 with errors='ignore' to handle raw binary bytes safely 
            # without throwing UnicodeDecodeError when encountering non-text protocol handshakes.
            banner_bytes = s.recv(1024)
            return banner_bytes.decode("utf-8", errors="ignore").strip().replace("\n", " ").replace("\r", "")
    except Exception:
        return "No banner retrieved"


def scan_port(target_ip: str, port: int, timeout: float) -> None:
    """Scans a single TCP port and grabs banner if open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            # Inline Comment 1: Timeout Rationale
            # A 1.0-second socket timeout strikes an optimal balance: it provides sufficient 
            # time for remote hosts to complete the TCP 3-way handshake while preventing 
            # threads from hanging indefinitely on filtered ports dropping packets.
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            
            if result == 0:
                banner = grab_banner(target_ip, port, timeout)
                # Inline Comment 2: Threading Lock Usage
                # The thread lock ensures synchronized, thread-safe access when appending 
                # open port records to the shared `open_ports` list, preventing race conditions.
                with print_lock:
                    open_ports.append((port, "OPEN", banner if banner else "Unknown"))
    except (ConnectionRefusedError, socket.timeout, OSError):
        # Gracefully swallow connection errors for closed or filtered ports
        pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Multithreaded TCP Port Scanner with Banner Grabbing")
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range (e.g., 1-1024)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--threads", type=int, default=100, help="Maximum worker threads (default: 100)")
    args = parser.parse_args()

    # Parse port range
    try:
        start_port, end_port = map(int, args.ports.split("-"))
    except ValueError:
        print("[-] Invalid port range format. Use START-END (e.g., 1-1024).")
        return

    print(f"[*] Starting scan on target {args.target} for ports {start_port}-{end_port}...")
    
    threads: List[threading.Thread] = []
    for port in range(start_port, end_port + 1):
        t = threading.Thread(target=scan_port, args=(args.target, port, args.timeout))
        threads.append(t)
        t.start()
        
        # Batch thread execution to prevent OS thread limit exhaustion
        if len(threads) >= args.threads:
            for thread in threads:
                thread.join()
            threads = []

    # Join remaining threads
    for thread in threads:
        thread.join()

    # Print Formatted Output Table
    print("\n" + "=" * 65)
    print(f"{'PORT':<10} | {'STATE':<10} | {'BANNER'}")
    print("=" * 65)
    for port, state, banner in sorted(open_ports, key=lambda x: x[0]):
        print(f"{port:<10} | {state:<10} | {banner[:40]}")
    print("=" * 65)
    print(f"[*] Scan complete. Found {len(open_ports)} open port(s).\n")


if __name__ == "__main__":
    main()