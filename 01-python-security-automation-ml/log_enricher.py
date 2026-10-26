#!/usr/bin/env python3
"""
Log Parser with Regex Public IP Extraction and Threat Intelligence Enrichment (ip-api.com)
Accurately identifies and isolates public IPv4 indicators using standard RFC rules
via Python's ipaddress library.
"""

import argparse
import ipaddress
import json
import re
import sys
from typing import Dict, Optional, Set
import requests


def is_public_ip(ip: str) -> bool:
    """
    Checks if an IP string is a valid, globally routable public IP address.
    Correctly excludes RFC 1918 private ranges, loopback (127.0.0.0/8),
    link-local (169.254.0.0/16), carrier-grade NAT (100.64.0.0/10),
    multicast, reserved, and unspecified addresses.
    """
    try:
        addr = ipaddress.ip_address(ip)
        return addr.is_global and not (
            addr.is_multicast or addr.is_reserved or addr.is_link_local
        )
    except ValueError:
        return False


def extract_public_ips(log_file_path: str) -> Set[str]:
    """
    Reads log file and extracts unique, valid public IPv4 addresses.
    """
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    public_ips: Set[str] = set()

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                for candidate in ip_pattern.findall(line):
                    if is_public_ip(candidate):
                        public_ips.add(candidate)
    except FileNotFoundError:
        print(f"[-] Error: File not found at '{log_file_path}'", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[-] Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    return public_ips


def enrich_ip(ip: str, timeout: float = 5.0, session: Optional[requests.Session] = None) -> Dict:
    """
    Queries ip-api.com REST API for IP geolocation and proxy/hosting threat data.
    Gracefully handles rate limiting (HTTP 429) and network timeouts.
    """
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,hosting,proxy,mobile"
    req = session if session is not None else requests

    try:
        response = req.get(url, timeout=timeout)
        if response.status_code == 429:
            return {"error": "API Rate limit exceeded (429 Too Many Requests)"}
        response.raise_for_status()
        data = response.json()

        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "hosting": data.get("hosting", False),
                "proxy": data.get("proxy", False),
                "mobile": data.get("mobile", False),
            }
        else:
            return {"error": data.get("message", "API query failed")}
    except requests.exceptions.Timeout:
        return {"error": "HTTP Request timed out"}
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse API JSON response"}


def enrich_logs(log_file_path: str, timeout: float = 5.0) -> Dict[str, Dict]:
    """
    Extracts all public IPs from the log file and enriches each one.
    """
    public_ips = extract_public_ips(log_file_path)
    results: Dict[str, Dict] = {}
    with requests.Session() as session:
        for ip in sorted(public_ips):
            results[ip] = enrich_ip(ip, timeout=timeout, session=session)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Extract public IPs from logs and enrich via ip-api.com"
    )
    parser.add_argument("pos_logfile", nargs="?", default=None, help="Path to log file (positional)")
    parser.add_argument("-f", "--file", "--log", dest="flag_logfile", default=None, help="Path to log file (flag)")
    parser.add_argument("-o", "--output", help="Optional path to save JSON results")
    parser.add_argument("-t", "--timeout", type=float, default=5.0, help="HTTP timeout in seconds (default: 5.0)")
    args = parser.parse_args()

    logfile = args.flag_logfile or args.pos_logfile
    if not logfile:
        parser.error("Log file path is required. Specify positionally or with --file.")

    results = enrich_logs(logfile, timeout=args.timeout)
    formatted_json = json.dumps(results, indent=4)
    print(formatted_json)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(formatted_json)
            print(f"[+] Enrichment output written to '{args.output}'", file=sys.stderr)
        except OSError as e:
            print(f"[-] Failed to write output file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
