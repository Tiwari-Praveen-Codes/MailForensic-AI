
# 🛡️ MailForensic AI

## AI-Powered Email Threat Detection, Digital Forensics & Evidence Integrity

MailForensic AI is an intelligent email-security and digital-forensics platform that combines **Machine Learning, Email Header Forensics, Threat Intelligence, URL/QR Analysis, Geolocation, Explainable Risk Scoring, and Blockchain-backed Evidence Integrity** into a unified investigation workflow.

> **Detect → Investigate → Explain → Preserve Evidence**

---

## 🚨 Problem

Modern email attacks are becoming increasingly sophisticated:

- Phishing and Business Email Compromise (BEC)
- Sender and domain spoofing
- Malicious URLs and QR-based phishing (Quishing)
- Malware delivery
- Brand impersonation
- Homoglyph and typosquatting attacks
- Forged or suspicious email headers
- Multi-stage redirects
- Difficult-to-preserve digital evidence

Traditional email-security systems primarily focus on **detection and blocking**.

MailForensic AI extends this workflow by combining **threat detection, forensic investigation, threat intelligence correlation, explainable risk assessment, and evidence integrity verification**.

---

## 🎯 Key Features

| Feature | Description |
|---|---|
| 🤖 AI Threat Detection | Detects phishing, BEC, spoofing, malware and suspicious emails |
| 🔍 Email Forensics | Analyzes headers, routing chains, authentication and origin information |
| 🌐 URL Intelligence | Detects malicious URLs, redirects, suspicious domains and phishing patterns |
| 📱 QR / Quishing Detection | Extracts and analyzes URLs embedded inside QR codes |
| 🧠 Explainable Risk Scoring | Combines multiple security signals into a unified risk score |
| 🌍 Geolocation Intelligence | Maps suspicious IP addresses and threat origins |
| 🛡️ Threat Intelligence | Correlates indicators with external security intelligence |
| ⛓️ Blockchain Evidence Integrity | Anchors evidence fingerprints on Monad Testnet |
| 📄 Forensic Reports | Generates investigation-ready PDF reports |
| 📊 Security Dashboard | Provides threat trends, distributions and geographic intelligence |

---

## 🏗️ System Architecture

```text
                         ┌─────────────────────────┐
                         │       USER / SOC         │
                         │  Security Analyst / IR   │
                         └────────────┬────────────┘
                                      │
                                      ▼
                         ┌─────────────────────────┐
                         │    PRESENTATION LAYER    │
                         │ React + TypeScript +     │
                         │ Vite + Chart.js + Leaflet│
                         └────────────┬────────────┘
                                      │
                                      ▼
                    ┌──────────────────────────────────┐
                    │          API / ORCHESTRATION      │
                    │              Flask                │
                    └───────────────┬──────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
              ▼                     ▼                     ▼
      ┌──────────────┐      ┌───────────────┐     ┌──────────────┐
      │ AI Detection │      │ Email Forensics│     │ Threat Intel │
      └──────┬───────┘      └───────┬───────┘     └──────┬───────┘
             │                      │                      │
             ▼                      ▼                      ▼
      ┌──────────────┐      ┌───────────────┐     ┌──────────────┐
      │ XGBoost      │      │ SPF / DKIM    │     │ VirusTotal   │
      │ LightGBM     │      │ DMARC         │     │ Safe Browse  │
      │ DistilBERT   │      │ Header Chain  │     │ AbuseIPDB    │
      └──────────────┘      │ Origin IP     │     │ PhishTank    │
                            │ URL / QR      │     │ RDAP         │
                            └───────────────┘     └──────────────┘
                                      │
                                      ▼
                           ┌────────────────────┐
                           │ Explainable Risk    │
                           │     Engine          │
                           └─────────┬──────────┘
                                     │
                  ┌──────────────────┴──────────────────┐
                  │                                     │
                  ▼                                     ▼
        ┌──────────────────┐                  ┌──────────────────┐
        │ Geolocation &    │                  │ Forensic Report  │
        │ Threat Mapping   │                  │ PDF Generation   │
        └──────────────────┘                  └────────┬─────────┘
                                                       │
                                                       ▼
                                           ┌──────────────────────┐
                                           │ Evidence Integrity   │
                                           │   Monad Testnet      │
                                           └──────────────────────┘
```

---

## 🔄 End-to-End Investigation Workflow

```text
Email Input
     │
     ▼
Email Parsing
     │
     ├── Header Extraction
     ├── URL Extraction
     ├── QR Extraction
     └── Content Analysis
     │
     ▼
AI Threat Detection
     │
     ▼
Authentication Analysis
     │
     ├── SPF
     ├── DKIM
     └── DMARC
     │
     ▼
Threat Intelligence Correlation
     │
     ├── Domain
     ├── IP
     ├── URL
     └── Reputation
     │
     ▼
Geolocation & Forensic Analysis
     │
     ▼
Explainable Risk Engine
     │
     ▼
Threat Classification
     │
     ├── Safe
     ├── Low
     ├── Medium
     ├── High
     └── Critical
     │
     ▼
Forensic Report
     │
     ▼
Evidence Hash
     │
     ▼
Monad Blockchain Verification
```

---

## 🤖 AI Threat Detection

MailForensic AI uses multiple machine-learning approaches for email threat classification.

### Models

- **XGBoost**
- **LightGBM**
- **DistilBERT**
- **3-Model Ensemble**

### Dataset

- 7 curated datasets
- 34,000+ emails
- 19 handcrafted security features

### Reported Test Metrics

| Model | Accuracy | Precision | Recall | F1 | AUC |
|---|---:|---:|---:|---:|---:|
| XGBoost | 97.39% | 94.82% | 97.54% | 96.16% | 0.9957 |
| LightGBM | 97.56% | 95.40% | 97.42% | 96.40% | 0.9959 |
| DistilBERT | 98.92% | 98.44% | 98.32% | 98.38% | 0.9991 |
| Full Ensemble | 98.9% | 98.4% | 98.3% | 98.4% | 0.999 |

> Metrics are reported from the project's test evaluation and depend on the underlying datasets, preprocessing and evaluation setup.

---

## 🧠 Explainable Risk Scoring

Instead of relying on a single ML prediction, MailForensic AI combines multiple security signals.

### Risk Score Components

| Signal | Weight |
|---|---:|
| ML Prediction | 20% |
| Threat Intelligence | 20% |
| URL Intelligence | 15% |
| Authentication | 15% |
| Geolocation | 15% |
| Forensic Header Trust | 8% |
| Content / Cognitive Analysis | 7% |

### Risk Classification

| Score | Classification |
|---:|---|
| `< 15` | 🟢 Safe |
| `15–29` | 🟡 Low |
| `30–49` | 🟠 Medium |
| `50–69` | 🔴 High |
| `≥ 70` | 🚨 Critical |

---

## 🔍 Email Forensics

### Header Analysis

- Received-header routing chain
- Origin IP extraction
- X-Originating-IP
- Sender authentication
- Display-name spoofing
- Header trust analysis

### Email Authentication

- SPF
- DKIM
- DMARC

### Domain Analysis

- Brand impersonation
- Homoglyph detection
- Look-alike domains
- Typosquatting
- Suspicious TLDs
- Punycode
- Excessive subdomains

### URL Analysis

- Malicious URL detection
- Phishing URL paths
- Redirect-chain analysis
- Suspicious downloads
- Encoded URLs
- TOR `.onion` addresses

### QR / Quishing Analysis

The platform can extract URLs from QR codes embedded inside emails and analyze the resulting destination for phishing or malicious indicators.

---

## 🌐 Threat Intelligence

MailForensic AI correlates email indicators against multiple threat-intelligence sources.

### Integrated Intelligence Sources

- VirusTotal
- Google Safe Browsing
- AbuseIPDB
- PhishTank
- RDAP
- GeoIP / IP intelligence

```text
Email
 │
 ├── Domain
 ├── URL
 ├── IP Address
 └── Hash
        │
        ▼
Threat Intelligence
        │
        ▼
Reputation + Indicators
        │
        ▼
Risk Engine
```

---

## 🌍 Geolocation Intelligence

Suspicious IP addresses can be mapped to geographic information to support investigation.

The dashboard can visualize:

- Origin IP
- Geographic location
- Threat distribution
- Suspicious sources
- Geographic threat trends

---

## ⛓️ Blockchain Evidence Integrity

MailForensic AI uses **Monad Testnet** to provide an integrity layer for forensic evidence.

> **Blockchain is used for evidence integrity and verification — not as the primary threat detection engine.**

The AI and forensic engines perform detection and investigation.

The blockchain layer provides a verifiable record of the evidence fingerprint and selected metadata.

### Smart Contract

```text
contracts/
└── EmailThreatRegistry.sol
```

### Network

```text
Network: Monad Testnet
Chain ID: 10143
```

### Stored Evidence Metadata

- Email SHA-256 hash
- Sender domain
- Threat type
- Risk score
- IPFS report hash
- Origin IP
- Reporter address
- Timestamp
- Existence status

### Verification Flow

```text
Email / Forensic Report
          │
          ▼
      SHA-256 Hash
          │
          ▼
   Evidence Registry
          │
          ▼
    Monad Testnet
          │
          ▼
 Hash Verification
```

The original email does **not** need to be publicly stored on-chain. The blockchain layer is intended to provide a verifiable fingerprint and audit trail.

---

## 📊 Security Dashboard

The dashboard provides a centralized view of email threats and forensic intelligence.

### Dashboard Capabilities

- Threat statistics
- Threat distribution
- Threat trends
- Authentication trends
- Top threat sources
- Geographic threat maps
- Risk-level distribution
- Investigation results

### Frontend

- React
- TypeScript
- Vite
- Chart.js
- Leaflet.js

---

## 🧩 Technology Stack

| Layer | Technology |
|---|---|
| Frontend | React, TypeScript, Vite |
| Backend | Python, Flask, Flask-SocketIO |
| Database | SQLite, SQLAlchemy |
| ML | Scikit-learn, XGBoost, LightGBM |
| NLP | PyTorch, Transformers, DistilBERT |
| AI Analysis | Gemini / LLM-based cognitive analysis |
| Email | Gmail API, OAuth 2.0 |
| Threat Intelligence | VirusTotal, Safe Browsing, AbuseIPDB, PhishTank, RDAP |
| Geolocation | MaxMind GeoLite2, IP intelligence |
| Blockchain | Solidity, Web3.py, Monad Testnet |
| Reports | ReportLab |
| Deployment | Docker, Docker Compose, Render |

---

## 📁 Project Structure

```text
MailForensic-AI/
│
├── backend/
│   ├── ml/
│   ├── ml_pipeline/
│   ├── services/
│   ├── routes/
│   ├── app.py
│   ├── models.py
│   └── extensions.py
│
├── contracts/
│   └── EmailThreatRegistry.sol
│
├── scripts/
│   └── deploy_monad.py
│
├── dashboard/
│   └── templates/
│
├── frontend/
│
├── training/
│   ├── Email_Threat_Detection_Training.ipynb
│   └── datasets/
│
├── tests/
│
├── Dockerfile
├── docker-compose.yml
├── render.yaml
├── requirements.txt
├── requirements-torch.txt
└── README.md
```

---

## 🔌 API

### Health

```http
GET /api/health
```

### Statistics

```http
GET /api/stats
```

### Email Scanning

```http
POST /email/api/scan/text
POST /email/api/scan/gmail
```

### Forensic Analysis

```http
POST /forensic/api/analyze
POST /forensic/api/analyze-eml
```

### PDF Report

```http
GET /forensic/api/report/pdf/<id>
```

### Threat Intelligence

```http
GET /api/threat-intel/summary
GET /api/threat-intel/trends
GET /api/threat-intel/distribution
GET /api/threat-intel/top-sources
GET /api/threat-intel/auth-trends
```

### Geolocation

```http
GET /api/geo/threats
```

### Real-Time Scan

```text
WebSocket: start_demo_scan
```

---

## 🚀 Getting Started

### 1. Clone Repository

```bash
git clone https://github.com/Tiwari-Praveen-Codes/MailForensic-AI.git
cd MailForensic-AI
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

### Windows

```bash
venv\Scripts\activate
```

### Linux / macOS

```bash
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

For PyTorch-based functionality:

```bash
pip install -r requirements-torch.txt
```

### 4. Configure Environment Variables

Create a `.env` file and configure the required credentials for:

- Gmail API
- Gemini / LLM
- VirusTotal
- Google Safe Browsing
- AbuseIPDB
- GeoIP
- Monad / Web3

> Never commit private keys or API credentials to the repository.

### 5. Run Backend

```bash
python backend/app.py
```

### 6. Run Frontend

```bash
cd frontend
npm install
npm run dev
```

---

## 🐳 Docker

Run the complete application using Docker Compose:

```bash
docker compose up --build
```

---

## 🧪 Testing

The project currently includes **95 tests** covering core application functionality.

Run:

```bash
pytest
```

---

## 🧠 Model Training

The project includes a dedicated training notebook:

```text
training/Email_Threat_Detection_Training.ipynb
```

### Training Workflow

```text
Datasets
   │
   ▼
Data Cleaning
   │
   ▼
Feature Engineering
   │
   ▼
Model Training
   │
   ├── XGBoost
   ├── LightGBM
   └── DistilBERT
   │
   ▼
Evaluation
   │
   ▼
Ensemble
   │
   ▼
Threat Detection
```

---

## 🔐 Security Considerations

MailForensic AI processes potentially sensitive email content.

Recommended deployment practices:

- Never commit API keys or private keys.
- Store secrets using environment variables.
- Restrict access to forensic reports.
- Protect Gmail OAuth credentials.
- Use HTTPS in production.
- Validate uploaded `.eml` files.
- Restrict blockchain reporter authorization.
- Avoid storing unnecessary sensitive email content.
- Treat external threat-intelligence responses as untrusted data.

---

## 🎯 Key Differentiator

Traditional email-security systems often focus primarily on:

```text
Detect → Block
```

MailForensic AI extends this workflow:

```text
Detect
  ↓
Investigate
  ↓
Correlate Threat Intelligence
  ↓
Explain Risk
  ↓
Generate Forensic Evidence
  ↓
Verify Evidence Integrity
```

The platform is designed not only to identify suspicious emails, but also to support **security investigation and evidence verification**.

---

## 📌 Current System Scope

### Detection

- Phishing
- BEC
- Spoofing
- Malware
- Suspicious URLs
- Quishing

### Investigation

- Email headers
- Authentication
- IP intelligence
- Domain intelligence
- URL analysis
- Geolocation
- Threat intelligence

### Evidence

- Forensic PDF reports
- SHA-256 evidence fingerprinting
- Blockchain verification
- Audit-oriented metadata

---

## 📜 License

This project is licensed under the **MIT License**.

---

## 👨‍💻 Project

### MailForensic AI

AI-powered email threat detection, digital forensics and blockchain-backed evidence integrity.

**Built using:**

`Python` • `React` • `Machine Learning` • `Threat Intelligence` • `Digital Forensics` • `Web3` • `Monad`
