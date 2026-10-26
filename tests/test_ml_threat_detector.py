import sys
from pathlib import Path
import warnings

# Suppress pyarrow dependency warning
warnings.filterwarnings("ignore", category=DeprecationWarning)

import pandas as pd

# Ensure module directory is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent / "01-python-security-automation-ml"))

from ml_threat_detector import (
    generate_or_load_dataset,
    parse_log_line,
    run_log_inference_mode,
    run_benchmark_mode,
)


def test_generate_or_load_dataset():
    df = generate_or_load_dataset()
    assert isinstance(df, pd.DataFrame)
    assert len(df) == 5000
    assert "label" in df.columns
    assert set(df["label"].unique()) == {0, 1}


def test_parse_log_line_firewall_drop():
    log = "2026-08-15T10:14:12Z firewall-01 kernel: [INBOUND DROP] IN=eth0 OUT= SRC=1.1.1.1 DST=192.168.1.100 PROTO=UDP SPT=53 DPT=53"
    res = parse_log_line(log)
    assert res is not None
    assert res["src_ip"] == "1.1.1.1"
    assert res["dest_ip"] == "192.168.1.100"
    assert res["proto"] == 2  # UDP
    assert res["rejected_event"] == 1
    assert res["is_public_src"] == 1


def test_parse_log_line_ssh_failed():
    log = "2026-08-15T10:14:05Z auth-server sshd[4102]: Failed password for invalid user admin from 10.0.0.15 port 49152 ssh2"
    res = parse_log_line(log)
    assert res is not None
    assert res["src_ip"] == "10.0.0.15"
    assert res["dest_port"] == 22
    assert res["failed_auth"] == 1
    assert res["sensitive_port"] == 1
    assert res["is_public_src"] == 0  # RFC 1918 private


def test_parse_log_line_ssh_accepted():
    log = "2026-08-15T10:14:30Z auth-server sshd[4115]: Accepted publickey for secops from 93.184.216.34 port 52100 ssh2"
    res = parse_log_line(log)
    assert res is not None
    assert res["src_ip"] == "93.184.216.34"
    assert res["accepted_event"] == 1
    assert res["failed_auth"] == 0


def test_parse_log_line_empty():
    assert parse_log_line("") is None
    assert parse_log_line("   ") is None


def test_run_log_inference_mode():
    sample_file = Path(__file__).parent.parent / "01-python-security-automation-ml" / "sample_logs.txt"
    results = run_log_inference_mode(str(sample_file))
    assert len(results) == 7
    malicious = [r for r in results if r["random_forest_classification"] == "MALICIOUS"]
    benign = [r for r in results if r["random_forest_classification"] == "BENIGN"]
    assert len(malicious) > 0
    assert len(benign) > 0


def test_run_benchmark_mode():
    metrics = run_benchmark_mode()
    assert "rf_accuracy" in metrics
    assert "iso_accuracy" in metrics
    assert metrics["rf_accuracy"] > 0.80
