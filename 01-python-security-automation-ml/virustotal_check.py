#!/usr/bin/env python3
"""
VirusTotal Public API v3 IP Address Threat Intelligence Enrichment
Loads VT_API_KEY from environment variables or command-line options.
Provides mock demonstration mode for offline testing and CI environments.
"""

import argparse
from datetime import datetime, timezone
import json
import os
import sys
from typing import Dict, List, Optional
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def query_virustotal_ip(ip: str, api_key: str, timeout: float = 10.0) -> Dict:
    """Queries VirusTotal API v3 for IP reputation and analysis statistics."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key,
    }

    try:
        response = requests.get(url, headers=headers, timeout=timeout)

        if response.status_code == 401:
            return {"error": "Invalid VirusTotal API Key (401 Unauthorized)"}
        elif response.status_code == 429:
            return {"error": "API Rate limit exceeded (429 Too Many Requests)"}
        elif response.status_code == 404:
            return {"error": "IP address not found in VirusTotal database (404)"}

        response.raise_for_status()
        data = response.json()

        attributes = data.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        last_analysis_ts = attributes.get("last_analysis_date")

        last_analysis_date = (
            datetime.fromtimestamp(last_analysis_ts, tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            if last_analysis_ts
            else "N/A"
        )

        return {
            "malicious_count": stats.get("malicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "last_analysis_date": last_analysis_date,
        }

    except requests.exceptions.Timeout:
        return {"error": "HTTP Request timed out while querying VirusTotal"}
    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP Error querying VirusTotal: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse VirusTotal JSON response"}


def mock_virustotal_ip(ip: str) -> Dict:
    """Generates deterministic mock threat intelligence statistics for demonstration and testing."""
    known_mock_data = {
        "8.8.8.8": {
            "malicious_count": 0,
            "harmless_count": 88,
            "suspicious_count": 0,
            "last_analysis_date": "2026-08-15 10:00:00 UTC",
            "mock": True,
        },
        "185.220.101.5": {
            "malicious_count": 14,
            "harmless_count": 52,
            "suspicious_count": 4,
            "last_analysis_date": "2026-08-15 10:14:00 UTC",
            "mock": True,
        },
    }
    return known_mock_data.get(
        ip,
        {
            "malicious_count": 0,
            "harmless_count": 75,
            "suspicious_count": 0,
            "last_analysis_date": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "mock": True,
        },
    )


def check_ips(
    target_ips: List[str],
    api_key: Optional[str] = None,
    mock: bool = False,
    timeout: float = 10.0,
) -> Dict[str, Dict]:
    """Queries or mocks threat intelligence scores for a list of IP addresses."""
    results: Dict[str, Dict] = {}
    for ip in target_ips:
        if mock:
            results[ip] = mock_virustotal_ip(ip)
        else:
            if not api_key:
                results[ip] = {"error": "No VirusTotal API key configured"}
            else:
                results[ip] = query_virustotal_ip(ip, api_key, timeout=timeout)
    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Query VirusTotal v3 IP threat intelligence indicators"
    )
    parser.add_argument("pos_ips", nargs="*", default=[], help="IP addresses to analyze")
    parser.add_argument("-i", "--ip", action="append", dest="flag_ips", help="Specify IP address (can be repeated)")
    parser.add_argument("-k", "--api-key", help="VirusTotal API Key (overrides VT_API_KEY environment variable)")
    parser.add_argument("--mock", action="store_true", help="Run in mock demonstration mode without calling live API")
    parser.add_argument("-o", "--output", help="Optional path to export results as JSON")
    args = parser.parse_args()

    # Collect IPs from positional arguments and flags, defaulting to demo IPs if none provided
    all_ips = list(args.pos_ips)
    if args.flag_ips:
        all_ips.extend(args.flag_ips)
    if not all_ips:
        all_ips = ["8.8.8.8", "185.220.101.5"]

    api_key = args.api_key or os.getenv("VT_API_KEY")

    # If mock mode is requested, or if no key is configured and user didn't specify mock
    if args.mock:
        print("[*] Running in mock demonstration mode (VT_API_KEY not required)...", file=sys.stderr)
        results = check_ips(all_ips, mock=True)
    else:
        if not api_key or api_key == "your_virustotal_api_key_here":
            print("[-] Error: VT_API_KEY environment variable is missing or unconfigured.", file=sys.stderr)
            print("    Please set VT_API_KEY in .env, pass --api-key <key>, or use --mock for demonstration.", file=sys.stderr)
            sys.exit(1)
        results = check_ips(all_ips, api_key=api_key)

    formatted_json = json.dumps(results, indent=4)
    print(formatted_json)

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(formatted_json)
            print(f"[+] Output written to '{args.output}'", file=sys.stderr)
        except OSError as e:
            print(f"[-] Failed to write output file: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
