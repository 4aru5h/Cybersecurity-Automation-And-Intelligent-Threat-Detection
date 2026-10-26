#!/usr/bin/env python3
"""
Multithreaded TCP Port Scanner with Banner Grabbing
Standard library implementation (no external scanner binaries).
Features concurrent thread-pool scanning, resilient port list/range parsing,
single-pass banner grabbing, and one-time hostname resolution.
"""

import argparse
import concurrent.futures
import json
import re
import socket
import sys
from typing import Dict, List, Optional, Set, Tuple


def parse_port_specification(port_spec: str) -> List[int]:
    """
    Parses complex port specifications including ranges and comma-delimited lists.
    Examples: '80', '1-1024', '22,80,443', '80,8000-8080,8443'
    """
    ports: Set[int] = set()
    segments = [s.strip() for s in port_spec.split(",") if s.strip()]

    if not segments:
        raise ValueError("Empty port specification provided.")

    for segment in segments:
        if "-" in segment:
            parts = segment.split("-")
            if len(parts) != 2:
                raise ValueError(f"Invalid port range format: '{segment}'. Use START-END.")
            start, end = int(parts[0]), int(parts[1])
            if start > end:
                raise ValueError(f"Inverted port range: '{segment}'. Start must be <= End.")
            if start < 1 or end > 65535:
                raise ValueError(f"Port range '{segment}' out of bounds (1-65535).")
            ports.update(range(start, end + 1))
        else:
            port = int(segment)
            if port < 1 or port > 65535:
                raise ValueError(f"Port '{port}' out of bounds (1-65535).")
            ports.add(port)

    return sorted(list(ports))


def sanitize_banner(raw_banner: str) -> str:
    """Strips non-printable and control characters from captured banners."""
    cleaned = re.sub(r"[\r\n\t]+", " ", raw_banner)
    cleaned = re.sub(r"[^\x20-\x7E]", "", cleaned).strip()
    return cleaned if cleaned else "No banner retrieved"


def scan_single_port(target_ip: str, port: int, timeout: float) -> Optional[Tuple[int, str, str]]:
    """
    Scans a single TCP port and attempts immediate banner acquisition on the
    established socket to avoid double-connection overhead and dropped handshakes.
    """
    banner = "No banner retrieved"
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((target_ip, port))
            if result == 0:
                # Connected successfully; send lightweight generic probe for banner grabbing
                try:
                    s.settimeout(min(timeout, 1.0))
                    s.sendall(b"\r\n")
                    raw_data = s.recv(1024)
                    if raw_data:
                        banner = sanitize_banner(raw_data.decode("utf-8", errors="ignore"))
                except (socket.timeout, OSError):
                    # Service is open but produced no immediate banner
                    pass
                return (port, "OPEN", banner)
    except (ConnectionRefusedError, socket.timeout, OSError):
        pass
    return None


def scan_target(
    target: str,
    ports: List[int],
    timeout: float = 1.0,
    max_threads: int = 100,
) -> Tuple[str, List[Tuple[int, str, str]]]:
    """
    Executes a multithreaded port scan against the target host using ThreadPoolExecutor.
    Returns the resolved IP and a sorted list of open port records (port, state, banner).
    """
    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror as e:
        raise ValueError(f"Unable to resolve host '{target}': {e}")

    results: List[Tuple[int, str, str]] = []
    thread_count = min(max_threads, max(1, len(ports)))

    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        future_to_port = {
            executor.submit(scan_single_port, target_ip, port, timeout): port
            for port in ports
        }
        for future in concurrent.futures.as_completed(future_to_port):
            res = future.result()
            if res is not None:
                results.append(res)

    results.sort(key=lambda x: x[0])
    return target_ip, results


def format_scan_table(target: str, target_ip: str, open_ports: List[Tuple[int, str, str]]) -> str:
    """Formats scan results into a clean ASCII table."""
    lines: List[str] = [
        f"\nScan results for: {target} ({target_ip})",
        "=" * 65,
        f"{'PORT':<10} | {'STATE':<10} | {'BANNER'}",
        "=" * 65,
    ]
    if not open_ports:
        lines.append("No open ports discovered in specified range.")
    else:
        for port, state, banner in open_ports:
            display_banner = banner[:40] if banner else "No banner retrieved"
            lines.append(f"{port:<10} | {state:<10} | {display_banner}")
    lines.append("=" * 65)
    lines.append(f"[*] Scan complete. Found {len(open_ports)} open port(s).\n")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Multithreaded TCP Port Scanner with Banner Grabbing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Examples:\n"
               "  python port_scanner.py 127.0.0.1 -p 1-1024\n"
               "  python port_scanner.py --target 127.0.0.1 --ports 22,80,443\n"
               "  python port_scanner.py 192.168.1.1 -p 80,8080-8090 -t 0.5 -w 50\n"
    )
    # Support both positional target and --target / -T flag
    parser.add_argument("pos_target", nargs="?", default=None, help="Target IP address or hostname (positional)")
    parser.add_argument("-T", "--target", dest="flag_target", default=None, help="Target IP address or hostname (flag)")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port specification (e.g. 1-1024, 80, or 22,80,443)")
    parser.add_argument("-t", "--timeout", type=float, default=1.0, help="Socket timeout in seconds (default: 1.0)")
    parser.add_argument("-w", "--threads", type=int, default=100, help="Maximum worker threads (default: 100)")
    parser.add_argument("-o", "--output", help="Optional path to export scan results as JSON")
    args = parser.parse_args()

    # Determine target from either positional or flag argument
    target = args.flag_target or args.pos_target
    if not target:
        parser.error("Target host is required. Specify as positional argument or with --target.")

    # Parse port specification
    try:
        ports = parse_port_specification(args.ports)
    except ValueError as e:
        print(f"[-] Invalid port specification: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Initiating scan on {target} ({len(ports)} ports, timeout={args.timeout}s, threads={args.threads})...")

    try:
        target_ip, open_ports = scan_target(target, ports, timeout=args.timeout, max_threads=args.threads)
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    table_output = format_scan_table(target, target_ip, open_ports)
    print(table_output)

    if args.output:
        export_data = {
            "target": target,
            "target_ip": target_ip,
            "total_ports_scanned": len(ports),
            "open_ports_count": len(open_ports),
            "open_ports": [
                {"port": p, "state": s, "banner": b} for p, s, b in open_ports
            ],
        }
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=4)
            print(f"[+] Results exported to '{args.output}'")
        except OSError as e:
            print(f"[-] Failed to write output file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
