import sys
from pathlib import Path
from unittest.mock import MagicMock, patch
import requests

# Ensure module directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "01-python-security-automation-ml"))

from virustotal_check import query_virustotal_ip, mock_virustotal_ip, check_ips


@patch("requests.get")
def test_query_virustotal_ip_success(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {
        "data": {
            "attributes": {
                "last_analysis_stats": {
                    "malicious": 5,
                    "harmless": 80,
                    "suspicious": 1,
                },
                "last_analysis_date": 1700000000,
            }
        }
    }
    mock_get.return_value = mock_resp

    data = query_virustotal_ip("8.8.8.8", "mock_key")
    assert data["malicious_count"] == 5
    assert data["harmless_count"] == 80
    assert data["suspicious_count"] == 1
    assert "UTC" in data["last_analysis_date"]


@patch("requests.get")
def test_query_virustotal_ip_401(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 401
    mock_get.return_value = mock_resp

    data = query_virustotal_ip("8.8.8.8", "invalid_key")
    assert "401" in data["error"]


@patch("requests.get")
def test_query_virustotal_ip_404(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_get.return_value = mock_resp

    data = query_virustotal_ip("192.0.2.1", "mock_key")
    assert "404" in data["error"]


@patch("requests.get")
def test_query_virustotal_ip_429(mock_get):
    mock_resp = MagicMock()
    mock_resp.status_code = 429
    mock_get.return_value = mock_resp

    data = query_virustotal_ip("8.8.8.8", "mock_key")
    assert "429" in data["error"]


def test_mock_virustotal_ip():
    mock_res = mock_virustotal_ip("8.8.8.8")
    assert mock_res["malicious_count"] == 0
    assert mock_res["harmless_count"] == 88
    assert mock_res["mock"] is True

    tor_res = mock_virustotal_ip("185.220.101.5")
    assert tor_res["malicious_count"] == 14
    assert tor_res["suspicious_count"] == 4


def test_check_ips_mock_mode():
    res = check_ips(["8.8.8.8", "185.220.101.5"], mock=True)
    assert len(res) == 2
    assert res["8.8.8.8"]["mock"] is True
