import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import requests

# Ensure module directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "01-python-security-automation-ml"))

from log_enricher import is_public_ip, extract_public_ips, enrich_ip, enrich_logs


def test_is_public_ip_class_a_private():
    assert is_public_ip("10.0.0.1") is False
    assert is_public_ip("10.255.255.255") is False


def test_is_public_ip_class_b_private():
    assert is_public_ip("172.16.0.1") is False
    assert is_public_ip("172.31.255.255") is False
    assert is_public_ip("172.32.0.1") is True  # Public


def test_is_public_ip_class_c_private():
    assert is_public_ip("192.168.1.1") is False
    assert is_public_ip("192.168.254.254") is False


def test_is_public_ip_loopback():
    assert is_public_ip("127.0.0.1") is False
    assert is_public_ip("127.1.2.3") is False


def test_is_public_ip_link_local_and_cgnat():
    assert is_public_ip("169.254.1.1") is False  # Link-local
    assert is_public_ip("100.64.0.1") is False  # CGNAT


def test_is_public_ip_multicast_and_reserved():
    assert is_public_ip("224.0.0.1") is False  # Multicast
    assert is_public_ip("240.0.0.1") is False  # Reserved
    assert is_public_ip("0.0.0.0") is False  # Unspecified


def test_is_public_ip_public_addresses():
    assert is_public_ip("8.8.8.8") is True
    assert is_public_ip("1.1.1.1") is True
    assert is_public_ip("93.184.216.34") is True
    assert is_public_ip("185.220.101.5") is True


def test_is_public_ip_invalid_strings():
    assert is_public_ip("not-an-ip") is False
    assert is_public_ip("999.999.999.999") is False
    assert is_public_ip("") is False


def test_extract_public_ips_from_sample():
    sample_file = Path(__file__).parent.parent / "01-python-security-automation-ml" / "sample_logs.txt"
    ips = extract_public_ips(str(sample_file))
    # 8.8.8.8, 1.1.1.1, 185.220.101.5, 93.184.216.34, 114.114.114.114
    assert "8.8.8.8" in ips
    assert "1.1.1.1" in ips
    assert "185.220.101.5" in ips
    assert "93.184.216.34" in ips
    assert "114.114.114.114" in ips
    # Private IPs should NOT be present
    assert "10.0.0.15" not in ips
    assert "192.168.1.50" not in ips
    assert "172.16.0.22" not in ips


@patch("requests.get")
def test_enrich_ip_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "status": "success",
        "country": "United States",
        "isp": "Google LLC",
        "hosting": True,
        "proxy": False,
        "mobile": False,
    }
    mock_get.return_value = mock_resp

    data = enrich_ip("8.8.8.8")
    assert data["country"] == "United States"
    assert data["isp"] == "Google LLC"
    assert data["hosting"] is True


@patch("requests.get")
def test_enrich_ip_rate_limit(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    data = enrich_ip("8.8.8.8")
    assert "Rate limit exceeded" in data["error"]


@patch("requests.get")
def test_enrich_ip_timeout(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout("Connection timed out")
    data = enrich_ip("8.8.8.8")
    assert "timed out" in data["error"]
