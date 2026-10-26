#!/usr/bin/env python3
"""
Machine Learning Threat Detector
Trains Supervised Random Forest and Unsupervised Isolation Forest on Security Data.
Supports two operational modes:
  1. Synthetic Benchmark Mode: 5,000-sample dataset comparing Supervised vs Unsupervised models.
  2. Log Inference Mode (--input <log_file>): Parses firewall and auth logs, extracts security
     features, and flags anomalous and malicious events.
"""

import argparse
import ipaddress
import json
import re
import sys
from typing import Any, Dict, List, Optional, Tuple
import warnings

# Suppress pyarrow dependency warning from pandas
warnings.filterwarnings("ignore", category=DeprecationWarning)

import numpy as np
import pandas as pd
from sklearn.datasets import make_classification
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, precision_recall_fscore_support
from sklearn.model_selection import train_test_split


def generate_or_load_dataset() -> pd.DataFrame:
    """Generates synthetic security threat dataset (5,000 samples) mirroring UCI Phishing structure."""
    X_raw, y_raw = make_classification(
        n_samples=5000,
        n_features=10,
        n_informative=8,
        n_redundant=2,
        weights=[0.85, 0.15],  # Imbalanced: 85% Benign (0), 15% Malicious (1)
        random_state=42,
    )
    feature_names = [f"feature_{i+1}" for i in range(10)]
    df = pd.DataFrame(X_raw, columns=feature_names)
    df["label"] = y_raw
    return df


def run_benchmark_mode() -> Dict[str, Any]:
    """Runs the 5,000-sample synthetic benchmark comparing Random Forest and Isolation Forest."""
    print("=" * 65)
    print(" 1. DATASET LOADING & PREPROCESSING")
    print("=" * 65)
    df = generate_or_load_dataset()

    print("\n[+] First 5 Rows of Dataset:")
    print(df.head())

    print("\n[+] Class Distribution:")
    print(df["label"].value_counts().rename({0: "Benign (0)", 1: "Malicious (1)"}))

    initial_count = len(df)
    df = df.dropna().drop_duplicates()
    duplicates_removed = initial_count - len(df)
    print(f"\n[+] Preprocessing Complete: Removed {duplicates_removed} duplicate rows.")

    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Data Split: Train={len(X_train)} samples, Test={len(X_test)} samples")

    # -------------------------------------------------------------
    # 2. MODEL 1: SUPERVISED RANDOM FOREST CLASSIFIER
    # -------------------------------------------------------------
    print("\n" + "=" * 65)
    print(" 2. SUPERVISED RANDOM FOREST CLASSIFIER")
    print("=" * 65)
    rf_model = RandomForestClassifier(random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)

    rf_report = classification_report(
        y_test, rf_preds, target_names=["Benign", "Malicious"], zero_division=0
    )
    print("\n[+] Random Forest Classification Report:\n")
    print(rf_report)

    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(
        y_test, rf_preds, average="binary", zero_division=0
    )

    # -------------------------------------------------------------
    # 3. MODEL 2: UNSUPERVISED ISOLATION FOREST ANOMALY DETECTOR
    # -------------------------------------------------------------
    print("=" * 65)
    print(" 3. UNSUPERVISED ISOLATION FOREST ANOMALY DETECTOR")
    print("=" * 65)
    iso_model = IsolationForest(contamination=0.15, random_state=42)
    iso_model.fit(X_train)

    raw_iso_preds = iso_model.predict(X_test)
    iso_preds = np.where(raw_iso_preds == -1, 1, 0)

    iso_acc = accuracy_score(y_test, iso_preds)
    iso_prec, iso_rec, iso_f1, _ = precision_recall_fscore_support(
        y_test, iso_preds, average="binary", zero_division=0
    )
    print(f"\n[+] Isolation Forest Anomaly Detection Accuracy: {iso_acc:.4f} ({iso_acc*100:.2f}%)")

    # -------------------------------------------------------------
    # 4. SUMMARY COMPARISON TABLE
    # -------------------------------------------------------------
    print("\n" + "=" * 65)
    print(" 4. MODEL COMPARISON SUMMARY")
    print("=" * 65)
    summary_df = pd.DataFrame([
        {
            "Model": "Random Forest (Supervised)",
            "Accuracy": f"{rf_acc:.4f}",
            "Precision": f"{rf_prec:.4f}",
            "Recall": f"{rf_rec:.4f}",
            "F1 Score": f"{rf_f1:.4f}",
            "Notes": "Supervised ensemble; highly accurate on known threat features.",
        },
        {
            "Model": "Isolation Forest (Unsupervised)",
            "Accuracy": f"{iso_acc:.4f}",
            "Precision": f"{iso_prec:.4f}",
            "Recall": f"{iso_rec:.4f}",
            "F1 Score": f"{iso_f1:.4f}",
            "Notes": "Anomaly detector; flags outliers without ground-truth labels.",
        },
    ])
    print(summary_df.to_string(index=False))

    return {
        "rf_accuracy": float(rf_acc),
        "rf_f1": float(rf_f1),
        "iso_accuracy": float(iso_acc),
        "iso_f1": float(iso_f1),
    }


def parse_log_line(line: str) -> Optional[Dict[str, Any]]:
    """Extracts numerical and categorical security features from a single log record."""
    line = line.strip()
    if not line:
        return None

    # Default feature values
    src_ip = "0.0.0.0"  # nosec: B104
    dest_ip = "0.0.0.0"  # nosec: B104
    src_port = 0
    dest_port = 0
    proto = 1  # 1=TCP, 2=UDP, 0=OTHER
    failed_auth = 0
    rejected_event = 0
    accepted_event = 0
    sensitive_port = 0

    # Match iptables / kernel firewall logs
    if "firewall" in line or "kernel:" in line:
        src_match = re.search(r"SRC=([0-9.]+)", line)
        dst_match = re.search(r"DST=([0-9.]+)", line)
        spt_match = re.search(r"SPT=(\d+)", line)
        dpt_match = re.search(r"DPT=(\d+)", line)
        proto_match = re.search(r"PROTO=(\w+)", line)

        if src_match:
            src_ip = src_match.group(1)
        if dst_match:
            dest_ip = dst_match.group(1)
        if spt_match:
            src_port = int(spt_match.group(1))
        if dpt_match:
            dest_port = int(dpt_match.group(1))
        if proto_match:
            proto_str = proto_match.group(1).upper()
            proto = 2 if proto_str == "UDP" else 1

        if "REJECT" in line or "DROP" in line:
            rejected_event = 1

    # Match SSH / auth logs
    elif "sshd" in line or "auth" in line:
        dest_port = 22
        proto = 1
        src_match = re.search(r"from ([0-9.]+)", line)
        port_match = re.search(r"port (\d+)", line)

        if src_match:
            src_ip = src_match.group(1)
        if port_match:
            src_port = int(port_match.group(1))

        if "Failed password" in line or "invalid user" in line:
            failed_auth = 1
        elif "Accepted" in line:
            accepted_event = 1

    # Check if target port is commonly attacked / sensitive
    if dest_port in {21, 22, 23, 25, 445, 1433, 3306, 3389, 4433, 5432}:
        sensitive_port = 1

    # Check if source IP is public (non-RFC 1918)
    is_public = 0
    try:
        addr = ipaddress.ip_address(src_ip)
        if not (addr.is_private or addr.is_loopback):
            is_public = 1
    except ValueError:
        pass

    return {
        "raw_log": line,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "src_port": src_port,
        "dest_port": dest_port,
        "proto": proto,
        "is_public_src": is_public,
        "failed_auth": failed_auth,
        "rejected_event": rejected_event,
        "accepted_event": accepted_event,
        "sensitive_port": sensitive_port,
    }


def run_log_inference_mode(log_file_path: str, output_path: Optional[str] = None) -> List[Dict[str, Any]]:
    """
    Parses a log file, extracts security features, trains the threat detectors,
    and classifies each event as Benign (0) vs Threat / Anomaly (1).
    """
    print("=" * 65)
    print(f" LOG-BASED THREAT DETECTION INFERENCE: '{log_file_path}'")
    print("=" * 65)

    parsed_events: List[Dict[str, Any]] = []
    try:
        with open(log_file_path, "r", encoding="utf-8") as f:
            for line in f:
                event = parse_log_line(line)
                if event:
                    parsed_events.append(event)
    except FileNotFoundError:
        print(f"[-] Error: Log file '{log_file_path}' not found.", file=sys.stderr)
        sys.exit(1)

    if not parsed_events:
        print("[-] No valid log events parsed from file.", file=sys.stderr)
        return []

    print(f"[+] Successfully extracted {len(parsed_events)} log event records.")

    feature_cols = [
        "src_port",
        "dest_port",
        "proto",
        "is_public_src",
        "failed_auth",
        "rejected_event",
        "accepted_event",
        "sensitive_port",
    ]

    features_df = pd.DataFrame(parsed_events)[feature_cols]

    # Reference training dataset of benign & malicious baseline traffic
    # to train the classifiers on network security features
    baseline_records = [
        # Benign internal & established web/dns traffic
        {"src_port": 52100, "dest_port": 22, "proto": 1, "is_public_src": 1, "failed_auth": 0, "rejected_event": 0, "accepted_event": 1, "sensitive_port": 1, "label": 0},
        {"src_port": 49100, "dest_port": 80, "proto": 1, "is_public_src": 0, "failed_auth": 0, "rejected_event": 0, "accepted_event": 1, "sensitive_port": 0, "label": 0},
        {"src_port": 50012, "dest_port": 443, "proto": 1, "is_public_src": 0, "failed_auth": 0, "rejected_event": 0, "accepted_event": 0, "sensitive_port": 0, "label": 0},
        {"src_port": 53535, "dest_port": 53, "proto": 2, "is_public_src": 0, "failed_auth": 0, "rejected_event": 0, "accepted_event": 0, "sensitive_port": 0, "label": 0},
        {"src_port": 51234, "dest_port": 443, "proto": 1, "is_public_src": 1, "failed_auth": 0, "rejected_event": 0, "accepted_event": 1, "sensitive_port": 0, "label": 0},
        # Malicious brute force & port probing
        {"src_port": 49152, "dest_port": 22, "proto": 1, "is_public_src": 0, "failed_auth": 1, "rejected_event": 0, "accepted_event": 0, "sensitive_port": 1, "label": 1},
        {"src_port": 50112, "dest_port": 22, "proto": 1, "is_public_src": 1, "failed_auth": 1, "rejected_event": 0, "accepted_event": 0, "sensitive_port": 1, "label": 1},
        {"src_port": 4433, "dest_port": 3389, "proto": 1, "is_public_src": 1, "failed_auth": 0, "rejected_event": 1, "accepted_event": 0, "sensitive_port": 1, "label": 1},
        {"src_port": 80, "dest_port": 3389, "proto": 1, "is_public_src": 1, "failed_auth": 0, "rejected_event": 1, "accepted_event": 0, "sensitive_port": 1, "label": 1},
        {"src_port": 80, "dest_port": 4433, "proto": 1, "is_public_src": 0, "failed_auth": 0, "rejected_event": 1, "accepted_event": 0, "sensitive_port": 1, "label": 1},
        {"src_port": 53, "dest_port": 53, "proto": 2, "is_public_src": 1, "failed_auth": 0, "rejected_event": 1, "accepted_event": 0, "sensitive_port": 0, "label": 1},
    ]
    train_df = pd.DataFrame(baseline_records)
    X_train = train_df[feature_cols]
    y_train = train_df["label"]

    rf = RandomForestClassifier(n_estimators=50, random_state=42)
    rf.fit(X_train, y_train)

    iso = IsolationForest(contamination=0.35, random_state=42)
    iso.fit(X_train)

    rf_preds = rf.predict(features_df)
    iso_raw = iso.predict(features_df)
    iso_preds = np.where(iso_raw == -1, 1, 0)

    results: List[Dict[str, Any]] = []
    print("\n" + "=" * 95)
    print(f"{'SRC IP':<16} | {'DST PORT':<8} | {'EVENT TYPE':<22} | {'ISOLATION FOREST':<18} | {'RANDOM FOREST'}")
    print("=" * 95)

    for i, ev in enumerate(parsed_events):
        event_desc = (
            "SSH Failed Auth" if ev["failed_auth"]
            else "SSH Accepted Auth" if ev["accepted_event"]
            else "FW Drop/Reject" if ev["rejected_event"]
            else "Traffic Flow"
        )
        iso_label = "ANOMALY (Threat)" if iso_preds[i] == 1 else "Normal (Benign)"
        rf_label = "MALICIOUS" if rf_preds[i] == 1 else "BENIGN"

        print(f"{ev['src_ip']:<16} | {ev['dest_port']:<8} | {event_desc:<22} | {iso_label:<18} | {rf_label}")

        results.append({
            "log": ev["raw_log"],
            "src_ip": ev["src_ip"],
            "dest_port": ev["dest_port"],
            "event_type": event_desc,
            "isolation_forest_anomaly": bool(iso_preds[i] == 1),
            "random_forest_classification": "MALICIOUS" if rf_preds[i] == 1 else "BENIGN",
        })

    print("=" * 95)
    threat_count = sum(1 for r in results if r["random_forest_classification"] == "MALICIOUS")
    print(f"[*] Analysis complete. {threat_count}/{len(results)} events identified as threat/malicious.\n")

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(results, f, indent=4)
        print(f"[+] Detailed findings exported to '{output_path}'")

    return results


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Machine Learning Threat Detection Pipeline (Supervised & Anomaly Detection)"
    )
    parser.add_argument("-i", "--input", help="Path to input log file to analyze (e.g. sample_logs.txt)")
    parser.add_argument("-o", "--output", help="Optional path to export inference results as JSON")
    parser.add_argument(
        "--benchmark",
        action="store_true",
        help="Run the 5,000-sample synthetic benchmark comparison",
    )
    args = parser.parse_args()

    if args.input:
        run_log_inference_mode(args.input, output_path=args.output)
    else:
        run_benchmark_mode()


if __name__ == "__main__":
    main()
