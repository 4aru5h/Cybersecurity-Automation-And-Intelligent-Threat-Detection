#!/usr/bin/env python3
"""
VirusTotal Public API v3 IP Address Threat Intelligence Enrichment
Loads VT_API_KEY from environment variables.
"""

import os
import sys
import json
from datetime import datetime
from typing import Dict, List
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


def query_virustotal_ip(ip: str, api_key: str) -> Dict:
    """Queries VirusTotal API v3 for IP reputation and analysis statistics."""
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {
        "accept": "application/json",
        "x-apikey": api_key
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
        
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
            datetime.utcfromtimestamp(last_analysis_ts).strftime("%Y-%m-%d %H:%M:%S UTC")
            if last_analysis_ts else "N/A"
        )

        return {
            "malicious_count": stats.get("malicious", 0),
            "harmless_count": stats.get("harmless", 0),
            "suspicious_count": stats.get("suspicious", 0),
            "last_analysis_date": last_analysis_date
        }

    except requests.exceptions.RequestException as e:
        return {"error": f"HTTP Error querying VirusTotal: {str(e)}"}
    except json.JSONDecodeError:
        return {"error": "Failed to parse VirusTotal JSON response"}


def main() -> None:
    api_key = os.getenv("VT_API_KEY")
    if not api_key or api_key == "your_virustotal_api_key_here":
        print("[-] Error: VT_API_KEY environment variable is missing or unconfigured.", file=sys.stderr)
        print("    Please copy .env.example to .env and insert a valid VirusTotal v3 API key.", file=sys.stderr)
        sys.exit(1)

    target_ips = ["8.8.8.8", "185.220.101.5"]
    if len(sys.argv) > 1:
        target_ips = sys.argv[1:]

    results: Dict[str, Dict] = {}
    for ip in target_ips:
        results[ip] = query_virustotal_ip(ip, api_key)

    print(json.dumps(results, indent=4))


if __name__ == "__main__":
    main()