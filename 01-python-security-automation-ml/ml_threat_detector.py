#!/usr/bin/env python3
"""
Machine Learning Threat Detector
Trains Supervised Random Forest and Unsupervised Isolation Forest on Security Dataset.
"""

import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, accuracy_score, precision_recall_fscore_support
from sklearn.datasets import make_classification


def generate_or_load_dataset() -> pd.DataFrame:
    """Generates synthetic security threat dataset (5000 samples) mirroring UCI Phishing structure."""
    X_raw, y_raw = make_classification(
        n_samples=5000,
        n_features=10,
        n_informative=8,
        n_redundant=2,
        weights=[0.85, 0.15],  # Imbalanced: 85% Benign (0), 15% Malicious (1)
        random_state=42
    )
    feature_names = [f"feature_{i+1}" for i in range(10)]
    df = pd.DataFrame(X_raw, columns=feature_names)
    df["label"] = y_raw
    return df


def main() -> None:
    print("=" * 60)
    print(" 1. DATASET LOADING & PREPROCESSING")
    print("=" * 60)
    df = generate_or_load_dataset()
    
    print("\n[+] First 5 Rows of Dataset:")
    print(df.head())
    
    print("\n[+] Class Distribution:")
    print(df["label"].value_counts().rename({0: "Benign (0)", 1: "Malicious (1)"}))
    
    # Preprocessing
    initial_count = len(df)
    df = df.dropna()
    df = df.drop_duplicates()
    duplicates_removed = initial_count - len(df)
    print(f"\n[+] Preprocessing Complete: Removed {duplicates_removed} duplicate rows.")

    # Train/Test Split (80/20)
    X = df.drop(columns=["label"])
    y = df["label"]
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    print(f"[+] Data Split: Train={len(X_train)} samples, Test={len(X_test)} samples")

    # -------------------------------------------------------------
    # 2. MODEL 1: SUPERVISED RANDOM FOREST CLASSIFIER
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print(" 2. SUPERVISED RANDOM FOREST CLASSIFIER")
    print("=" * 60)
    rf_model = RandomForestClassifier(random_state=42)
    rf_model.fit(X_train, y_train)
    rf_preds = rf_model.predict(X_test)
    
    rf_report = classification_report(y_test, rf_preds, target_names=["Benign", "Malicious"])
    print("\n[+] Random Forest Classification Report:\n")
    print(rf_report)

    rf_acc = accuracy_score(y_test, rf_preds)
    rf_prec, rf_rec, rf_f1, _ = precision_recall_fscore_support(y_test, rf_preds, average='binary')

    # -------------------------------------------------------------
    # 3. MODEL 2: UNSUPERVISED ISOLATION FOREST ANOMALY DETECTOR
    # -------------------------------------------------------------
    print("=" * 60)
    print(" 3. UNSUPERVISED ISOLATION FOREST ANOMALY DETECTOR")
    print("=" * 60)
    # Contamination set to minority class proportion (~15%)
    iso_model = IsolationForest(contamination=0.15, random_state=42)
    iso_model.fit(X_train)
    
    # Isolation Forest outputs -1 for anomalies (malicious) and 1 for normal (benign)
    raw_iso_preds = iso_model.predict(X_test)
    iso_preds = np.where(raw_iso_preds == -1, 1, 0)
    
    iso_acc = accuracy_score(y_test, iso_preds)
    iso_prec, iso_rec, iso_f1, _ = precision_recall_fscore_support(y_test, iso_preds, average='binary')
    print(f"\n[+] Isolation Forest Anomaly Detection Accuracy: {iso_acc:.4f} ({iso_acc*100:.2f}%)")

    # -------------------------------------------------------------
    # 4. SUMMARY COMPARISON TABLE
    # -------------------------------------------------------------
    print("\n" + "=" * 60)
    print(" 4. MODEL COMPARISON SUMMARY")
    print("=" * 60)
    summary_df = pd.DataFrame([
        {
            "Model": "Random Forest (Supervised)",
            "Accuracy": f"{rf_acc:.4f}",
            "Precision": f"{rf_prec:.4f}",
            "Recall": f"{rf_rec:.4f}",
            "F1 Score": f"{rf_f1:.4f}",
            "Notes": "Supervised ensemble; highly accurate on known threat features."
        },
        {
            "Model": "Isolation Forest (Unsupervised)",
            "Accuracy": f"{iso_acc:.4f}",
            "Precision": f"{iso_prec:.4f}",
            "Recall": f"{iso_rec:.4f}",
            "F1 Score": f"{iso_f1:.4f}",
            "Notes": "Anomaly detector; flags outliers without ground-truth labels."
        }
    ])
    print(summary_df.to_string(index=False))


if __name__ == "__main__":
    main()