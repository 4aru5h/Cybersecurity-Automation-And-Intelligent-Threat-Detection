#!/usr/bin/env python3
"""
Log Parser with Regex Public IP Extraction and Threat Intelligence Enrichment (ip-api.com)
"""

import argparse
import json
import re
import sys
from typing import Dict, List, Set
import requests


def is_private_ip(ip: str) -> bool:
    """Checks if an IPv4 address belongs to RFC 1918 private IP ranges or loopback."""
    parts = list(map(int, ip.split(".")))
    
    # 10.0.0.0/8
    if parts[0] == 10:
        return True
    # 172.16.0.0/12
    if parts[0] == 172 and 16 <= parts[1] <= 31:
        return True
    # 192.168.0.0/16
    if parts[0] == 192 and parts[1] == 168:
        return True
    # 127.0.0.0/8 (Loopback)
    if parts[0] == 127:
        return True
        
    return False


def extract_public_ips(log_file_path: str) -> Set[str]:
    """Reads log file and extracts unique public IPv4 addresses using regular expressions."""
    # Matches IPv4 dotted-decimal format
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    public_ips: Set[str] = set()

    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                matches = ip_pattern.findall(line)
                for ip in matches:
                    # Validate individual octets <= 255
                    octets = ip.split(".")
                    if all(0 <= int(o) <= 255 for o in octets):
                        if not is_private_ip(ip):
                            public_ips.add(ip)
    except FileNotFoundError:
        print(f"[-] Error: File not found at '{log_file_path}'", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"[-] Error reading log file: {e}", file=sys.stderr)
        sys.exit(1)

    return public_ips


def enrich_ip(ip: str) -> Dict:
    """Queries ip-api.com REST API for IP geolocation and proxy/hosting threat data."""
    url = f"http://ip-api.com/json/{ip}?fields=status,message,country,isp,hosting,proxy,mobile"
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        data = response.json()
        
        if data.get("status") == "success":
            return {
                "country": data.get("country", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "hosting": data.get("hosting", False),
                "proxy": data.get("proxy", False),
                "mobile": data.get("mobile", False)
            }
        else:
            return {"error": data.get("message", "API query failed")}
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP Request failed: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse API JSON response"}


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract public IPs from logs and enrich via ip-api.com")
    parser.add_argument("logfile", help="Path to log file")
    args = parser.parse_args()

    public_ips = extract_public_ips(args.logfile)
    
    enrichment_results: Dict[str, Dict] = {}
    for ip in sorted(public_ips):
        enrichment_results[ip] = enrich_ip(ip)

    print(json.dumps(enrichment_results, indent=4))


if __name__ == "__main__":
    main()