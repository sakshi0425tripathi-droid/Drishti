# 🛡️ Drishti | AI-Powered Indigenous Digital Forensics Framework
> **Indigenous. Offline-First. Court-Ready.**  
> *An AI-powered Digital Forensics Investigation Framework built for Police Investigators, Forensic Analysts, and Cybercrime Victims in India.*

---

## 📌 Problem Statement & Context
Digital financial fraud and cybercrime incidents in India have surged with the ubiquitous adoption of UPI, netbanking, and mobile messaging. Perpetrators routinely employ multi-stage social engineering—commencing with vishing calls, transmitting phishing links via WhatsApp, harvesting credentials/OTPs, logging in from disparate geolocations, and executing rapid layering across **mule account networks** to frustrate fund recovery.

Current forensic workflows suffer from fragmented evidence handling, manual cross-referencing across disparate formats (call logs, CSV statements, authentication logs, WhatsApp exports, and payment screenshots), and stringent evidentiary challenges under **Section 65B of the Indian Evidence Act** / **Section 63 of the Bharatiya Sakshya Adhiniyam (BSA)**.

**Drishti** solves this by providing an indigenous, unified, offline-first digital forensics platform that:
1. **Collects & Preserves**: Cryptographic SHA-256 Chain of Custody ledger with instant tamper-detection.
2. **Analyzes**: Unsupervised machine learning (`IsolationForest`) detecting anomalies in financial transactions and authentication sessions.
3. **Authenticates**: Error Level Analysis (ELA) and metadata forensics detecting image/PDF tampering and Photoshop alterations.
4. **Correlates**: Cross-source regex entity extraction and interactive multi-relational link graphs.
5. **Reconstructs**: Chronological multi-channel timeline reconstruction with a highlighted fraud attack window.
6. **Reports**: Court-ready statutory investigation reports citing Section 106 & 94 BNSS (Sec 102 & 91 CrPC).
7. **Empowers Victims**: Citizen emergency assistance portal (1930 Helpline, `cybercrime.gov.in`, instant police complaint drafting).

---

## 🛠️ Tech Stack
- **UI & Frontend**: Streamlit (Cyber-forensics dark theme with custom responsive CSS)
- **Data & Analytics**: pandas, numpy
- **Machine Learning**: scikit-learn (`IsolationForest` multi-feature anomaly detection)
- **Network Analysis & Graphs**: networkx, pyvis (Physics-based Barnes-Hut interactive network)
- **Visualizations**: plotly (Interactive anomaly scatter plots and chronological timelines)
- **Digital Image Forensics**: Pillow (Error Level Analysis ELA, difference matrices, EXIF/PNG metadata)
- **Document Forensics**: pypdf (PDF trailer, xref, producer, and modification timestamps)
- **Cryptography & Security**: hashlib (SHA-256 cryptographic digests)
- **Entity Extraction**: re (High-precision Indian phone, IP, UPI VPA, and bank account regex patterns)
- **AI Synthesis**: Offline smart forensic template with optional local Ollama LLM integration (`llama3`, `mistral`)

---

## 🚀 Quickstart & Run Steps

### Option A: Clean Virtual Environment (Recommended)

```bash
# 1. Open terminal in the project directory
cd drishti

# 2. (Optional) Create and activate a clean virtual environment
python -m venv venv
# On Windows:
venv\Scripts\activate
# On Linux/macOS:
source venv/bin/activate

# 3. Install all dependencies from requirements.txt
pip install -r requirements.txt

# 4. Launch the Streamlit application
streamlit run app.py
```

### Option B: One-Click Windows Launcher
Double-click `run_drishti.bat` in the project root to start the app immediately.

The app will open automatically in your browser at:  
👉 **`http://localhost:8501`**

---

## 🌟 Key Features & Tab-by-Tab Overview

### 1️⃣ Evidence Vault & Chain of Custody
- Computes SHA-256 cryptographic hashes for every exhibit on ingress.
- Displays an immutable Chain of Custody audit table compliant with Section 65B Indian Evidence Act.
- **The Star Demo Moment ("Simulate Tampering")**:
  - Click **"🚨 Simulate Tampering"** to modify bytes in `transactions.csv`.
  - Drishti immediately triggers a prominent **RED ALERT: CHAIN OF CUSTODY BREACH**, displaying the **Original Ingress Hash vs Tampered Hash** side-by-side.
  - Click **"♻️ Restore Original Bytes"** to re-verify and restore full cryptographic integrity.

### 2️⃣ AI Behavioral Anomaly Detection
- Runs an unsupervised `IsolationForest` model on transactions (amount, nocturnal hour, time gap, beneficiary novelty) and authentication logins (city geofence, unknown IP, suspicious device fingerprint).
- Assigns interpretable **Risk Scores (0–100)** with plain-English forensic explanations (e.g., *"Amount 14.8x higher than user average at 02:17 AM to new beneficiary 'Ramesh Traders'"*).
- Interactive Plotly scatter plot highlighting fraudulent debits and mule forwards in neon red.

### 3️⃣ Authenticity Check & Error Level Analysis (ELA)
- **Image ELA**: Re-compresses payment screenshots at 90% JPEG quality, computes difference matrices, and amplifies localized error rates to reveal manipulated text and altered amounts.
- **Metadata Inspector**: Uncovers software editing markers (e.g. `Adobe Photoshop 2024`) and missing EXIF tags.
- **Side-by-Side Comparison**: Compares `screenshot_original.png` vs `screenshot_edited.png`.
- **PDF Forensics**: Audits `fake_kyc_notice.pdf` for post-issuance modification dates and suspicious creation utilities (`Canva`, `iLovePDF`).

### 4️⃣ Forensic Link Graph
- Extracts entities (phones, IPv4, bank accounts, UPI IDs, URLs) across all evidence files.
- Identifies critical cross-source corroborations (e.g. `+91-98765-43210` appearing across Call Logs, WhatsApp, and KYC Notice).
- Renders an interactive NetworkX + PyVis topology with:
  - Physics spacing (`springLength: 300`, `gravitationalConstant: -15000`, `avoidOverlap: 1.0`).
  - Hover-only edge tooltips (clean canvas with zero label overlap).
  - Peripheral evidence exhibits (purple boxes placed on the outer orbit).
  - Prominent node sizing for Scammer, Victim, Attacker IP, and Mule Accounts.
  - Automatic centering on load (`network.fit()`).

### 5️⃣ Incident Timeline Reconstruction
- Unifies voice calls, chat messages, login records, and bank transactions into a single chronological axis.
- Features a **shaded red fraud attack window** (17-Oct 19:42 to 18-Oct 02:27) tracking the progression from vishing call to phishing link, session hijack, unauthorized debits, and mule dispersal.

### 6️⃣ Court-Ready Legal Case Report
- Generates a court-ready investigation report formatted for Indian law enforcement and judicial authorities.
- Specifies statutory police actions:
  - **Section 106 BNSS / Sec 102 CrPC**: Immediate debit freeze notices to HDFC Bank, ICICI Bank, and SBI.
  - **Section 94 BNSS / Sec 91 CrPC**: Subscriber identification notices to ISP (Excitel Broadband) for IP `103.87.212.45`.
  - Telecom CDR / CAF preservation for `+91-98765-43210`.
- 100% offline generation using an indigenous smart template, with an optional toggle to query a local **Ollama** model (`llama3`, `mistral`) if running.
- One-click export as `.TXT` or court-styled `.HTML`.
- Mandatory disclaimer: *"AI flags suspicious items for human investigator verification."*

### 7️⃣ Citizen & Victim Guidance Portal
- Golden-hour emergency checklist: Dial **1930** (National Cyber Crime Helpline) and register at **`cybercrime.gov.in`**.
- NLP-based scam classifier that identifies fraud type (KYC impersonation, UPI QR fraud, loan app extortion, task scams) from free-text descriptions.
- Pre-drafted formal police complaint letter ready to download and submit to local Cyber Cells.

---

## 📁 Repository Structure

```text
drishti/
├── app.py              # Main Streamlit Application & Multi-Tab Interface
├── hashing.py          # Cryptographic SHA-256 Hashing, Chain of Custody & Tamper Engine
├── anomaly.py          # IsolationForest Anomaly Model, Risk Scorer & Scatter Plot
├── authenticity.py     # Image Error Level Analysis (ELA), EXIF Forensics & PDF Inspector
├── entities.py         # Regex Entity Extractor & Cross-Source Link Detection
├── graph.py            # NetworkX Relational Multi-Graph & PyVis Interactive Engine
├── timeline.py         # Chronological Multi-Source Temporal Reconstruction & Attack Shading
├── report.py           # Legal Case Report Generator (Offline Template + Ollama Toggle)
├── demo_data.py        # Realistic Indian Cybercrime Synthetic Evidence Generator
├── demo_data/          # Generated Evidence Files (CSV, TXT, PNG, PDF)
│   ├── transactions.csv
│   ├── login_logs.csv
│   ├── call_logs.csv
│   ├── whatsapp_chat.txt
│   ├── screenshot_original.png
│   ├── screenshot_edited.png
│   └── fake_kyc_notice.pdf
├── requirements.txt    # Frozen Python Dependencies (unpinned for clean install)
├── run_drishti.bat     # Windows One-Click App Launcher
└── README.md           # Documentation & Evaluation Guide
```

---

## 🔒 Security & Privacy Guarantee
> **All processing happens locally. No evidence is sent to external servers.**  
> Drishti operates in an air-gapped, zero-telemetry environment ensuring complete confidentiality of sensitive law enforcement records and victim data.
