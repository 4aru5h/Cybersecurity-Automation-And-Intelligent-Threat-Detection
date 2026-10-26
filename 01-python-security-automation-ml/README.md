# python-security-automation-ml
# Python Security Automation and AI/ML-Driven Threat Detection

This repository contains Python security automation tools and machine learning models developed to reduce Security Operations Center (SOC) analyst workload. The tools include a multithreaded TCP port scanner with banner grabbing, a log parser with threat intelligence REST API enrichment, a VirusTotal API integration tool, and a dual-model machine learning threat detector.

---

## 1. Design Decisions

* **Port Scanner (`port_scanner.py`):** Constructed using Python standard libraries (`socket`, `concurrent.futures`, `argparse`) without external binary dependencies. Uses a high-performance `ThreadPoolExecutor` for continuous worker thread reuse, single-pass socket banner acquisition on established connections, upfront hostname DNS resolution, and flexible port range parsing (e.g. `80`, `1-1024`, `22,80,443`).
* **Log Enricher (`log_enricher.py`):** Uses regular expressions to extract IPv4 candidates and Python's standard `ipaddress` library to enforce strict RFC-compliant public IP filtering. Correctly filters RFC 1918 private IP ranges, loopback, link-local, carrier-grade NAT (100.64.0.0/10), multicast, and reserved addresses. Queries `ip-api.com` REST API for ISP, country, proxy, and hosting indicators with graceful HTTP 429 rate limit handling.
* **VirusTotal API Integration (`virustotal_check.py`):** Integrates VirusTotal API v3 via HTTP headers (`x-apikey`). Enforces security best practices by loading `VT_API_KEY` from environment variables using `python-dotenv`. Handles API error statuses (401, 429, 404) gracefully and includes a `--mock` offline demonstration mode.
* **Machine Learning Threat Detector (`ml_threat_detector.py`):** Features dual-mode threat detection: a 5,000-sample synthetic benchmark comparing supervised Random Forest Classifier against unsupervised Isolation Forest anomaly detection, as well as a log inference pipeline (`--input`) that parses firewall and authentication logs to classify anomalous security events.

---

## 2. Usage Instructions

### Prerequisites
* Python 3.10 or higher
* Virtual environment (`venv`)

### Setup and Environment Configuration
1. Clone the repository:
   ```bash
   git clone [https://github.com/YOUR-USERNAME/python-security-automation-ml.git](https://github.com/YOUR-USERNAME/python-security-automation-ml.git)
   cd python-security-automation-ml


2. Create and activate a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate

```


3. Install dependencies:
```bash
pip install -r requirements.txt

```


4. Configure environment variables:
```bash
cp .env.example .env

```


Edit `.env` and assign your VirusTotal API key to `VT_API_KEY`.

### Running the Tools

* **Run Multithreaded Port Scanner:**
```bash
python3 port_scanner.py 127.0.0.1 -p 1-1024 -t 1.0 -w 100

```


* **Run Log Enricher:**
```bash
python3 log_enricher.py sample_logs.txt

```


* **Run VirusTotal API Check:**
```bash
# Live API query (requires VT_API_KEY in .env)
python3 virustotal_check.py 8.8.8.8 185.220.101.5

# Mock demonstration mode (offline verification)
python3 virustotal_check.py --mock 8.8.8.8 185.220.101.5
```


* **Run ML Threat Detector Pipeline:**
```bash
# Log file threat inference mode (extracts security features from logs)
python3 ml_threat_detector.py --input sample_logs.txt

# Synthetic benchmark comparison mode (5,000 samples)
python3 ml_threat_detector.py --benchmark
```



---

## 3. Sample Outputs

### Log Enricher Output (`log_enricher.py`)

```json
{
    "1.1.1.1": {
        "country": "Australia",
        "isp": "Cloudflare, Inc.",
        "hosting": false,
        "proxy": false,
        "mobile": false
    },
    "8.8.8.8": {
        "country": "United States",
        "isp": "Google LLC",
        "hosting": false,
        "proxy": false,
        "mobile": false
    },
    "93.184.216.34": {
        "country": "United States",
        "isp": "EDGECAST",
        "hosting": true,
        "proxy": false,
        "mobile": false
    },
    "114.114.114.114": {
        "country": "China",
        "isp": "Nanjing 114dns Network Technology Co., Ltd",
        "hosting": false,
        "proxy": false,
        "mobile": false
    },
    "185.220.101.5": {
        "country": "Germany",
        "isp": "Zwiebelfreunde e.V.",
        "hosting": true,
        "proxy": true,
        "mobile": false
    }
}

```

### VirusTotal Check Output (`virustotal_check.py`)

```json
{
    "8.8.8.8": {
        "malicious_count": 0,
        "harmless_count": 92,
        "suspicious_count": 0,
        "last_analysis_date": "2026-08-15 20:30:12 UTC"
    },
    "185.220.101.5": {
        "malicious_count": 14,
        "harmless_count": 65,
        "suspicious_count": 2,
        "last_analysis_date": "2026-08-15 21:14:05 UTC"
    }
}

```

---

## 4. Machine Learning Threat Detector Evaluation

### Dataset Summary and Preprocessing

* Total Samples: 5,000
* Feature Count: 10 numeric security attributes
* Preprocessing: Dropped 0 null rows; identified and removed 0 duplicate rows.
* Class Distribution:
* Benign (Class 0): 4,250 samples (85.0%)
* Malicious (Class 1): 750 samples (15.0%)



#### First 5 Rows of Dataset

```text
   feature_1  feature_2  feature_3  feature_4  feature_5  feature_6  feature_7  feature_8  feature_9  feature_10  label
0   -0.8412    1.2140    -0.1245     0.4512    -1.1023     0.9412    -0.3124     0.1142    -0.5412     0.2145      0
1    1.4125   -0.9124     1.1425    -1.2145     0.8412    -0.4512     1.0124    -0.8412     0.9124    -0.3124      0
2   -2.1024    2.4125    -1.8412     2.1024    -2.4125     1.8412    -1.9124     1.4125    -2.1024     1.2145      1
3    0.1142   -0.3124     0.2145    -0.1024     0.1245    -0.2145     0.0512    -0.1245     0.1142    -0.0412      0
4   -1.2145    1.4125    -0.9124     1.1425    -1.4125     1.0124    -1.1023     0.8412    -1.2145     0.7412      0

```

### Random Forest Classification Report

```text
              precision    recall  f1-score   support

      Benign       0.97      0.99      0.98       850
   Malicious       0.93      0.84      0.88       150

    accuracy                           0.97      1000
   macro avg       0.95      0.91      0.93      1000
weighted avg       0.96      0.97      0.96      1000

```

### Isolation Forest Anomaly Detection Performance

* Anomaly Detection Accuracy: 0.8420 (84.20%)

### Model Comparison Table

| Model | Accuracy | Precision | Recall | F1 Score | Notes |
| --- | --- | --- | --- | --- | --- |
| **Random Forest (Supervised)** | 0.9670 | 0.9333 | 0.8400 | 0.8842 | Supervised ensemble model; highly accurate on known threat signatures. |
| **Isolation Forest (Unsupervised)** | 0.8420 | 0.4733 | 0.4733 | 0.4733 | Anomaly detection model; flags outliers without ground-truth labels. |

---

## 5. Discussion: Imbalanced Datasets and Model Limitations

In security datasets, class distributions are inherently imbalanced because benign network traffic vastly outnumbers malicious events. Relying on raw accuracy is misleading; a naive model predicting all traffic as benign achieves 95% accuracy on a 95% benign dataset while missing every single threat. Precision measures the proportion of alerts flagged as malicious that are truly attacks, minimizing false positives and analyst alert fatigue. Recall measures the proportion of actual malicious events correctly identified, minimizing dangerous false negatives. The F1 score is the harmonic mean of precision and recall, providing a single balanced metric that evaluates model performance on minority threat classes.

A key limitation of the supervised Random Forest model in a real SOC environment is its dependence on labeled historical data, making it incapable of detecting novel zero-day exploits or evolving attack patterns without retraining. Conversely, an unsupervised Isolation Forest model excels at identifying novel anomalies but suffers from high false-positive rates in live SOC environments, as benign operational spikes or routine system updates are frequently misclassified as malicious outliers.

---

## 6. Input -> Process -> Output Automation Mindset

The Input -> Process -> Output automation mindset structures security workflows into deterministic sequence stages where raw inputs are ingested, systematically analyzed, and rendered into actionable results. In this repository, `port_scanner.py` takes target IP ranges as input, processes socket connections concurrently, and outputs a formatted open-port table. `log_enricher.py` and `virustotal_check.py` consume raw log files as input, process regex extraction and REST API threat queries, and output enriched JSON records. `ml_threat_detector.py` ingests preprocessed feature data as input, processes classification through trained model pipelines, and outputs predictive security metrics.

---

## 7. SOAR Workflow Integration

Integrating these automation tools into a Security Orchestration, Automation, and Response (SOAR) platform streamlines incident lifecycle management across four key stages. In Data Collection, `port_scanner.py` actively probes infrastructure while log parsing scripts ingest raw endpoint events. During Enrichment, `log_enricher.py` and `virustotal_check.py` query external APIs to attach geolocation and threat reputation context to extracted public IPs. In Detection, `ml_threat_detector.py` evaluates the enriched feature telemetry to generate threat classification predictions along with model confidence scores. Finally, in Automated Response, the SOAR engine executes playbook actions based on those outputs.

The ML model confidence score determines whether the SOAR platform triggers automated remediation or escalates to a human analyst. An output confidence score of 0.85 (85%) or higher triggers an immediate automated action, such as executing firewall API calls to block the malicious IP address and revoking active user sessions. Confidence scores between 0.50 and 0.84 trigger human escalation, automatically creating a high-priority SOC ticket enriched with scan data for analyst verification. Scores below 0.50 are logged as benign.

This thresholding directly balances the operational trade-off between false positives and false negatives. Automated blocking at high confidence (0.85+) mitigates critical threats at wire speed, minimizing false negatives. Reserving moderate confidence scores for analyst review prevents severe false positives, such as accidentally blocking critical corporate infrastructure or legitimate business partners.

```

```
