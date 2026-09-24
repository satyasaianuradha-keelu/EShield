# EmailShield

### AI-Assisted Email Threat Detection, Geolocation & Forensic Investigation Platform

**Smart India Hackathon (SIH) Prototype**

> **Detect. Investigate. Stay Safe.**

EmailShield is a Flask-based cybersecurity prototype for analyzing suspicious emails and presenting the findings in an analyst-friendly forensic investigation workflow. It parses RFC 822/`.eml` messages, extracts security indicators, applies a transparent rule-based threat analysis engine, reconstructs mail-routing timelines, provides IP/domain intelligence, and generates downloadable PDF reports.

This repository is designed primarily as a **hackathon demonstration/prototype**, not as a production-grade email security gateway.

---

## ✨ Key Features

### 1. Email Analysis
- Upload `.eml` files for analysis.
- Paste raw email content directly into the application.
- Parses:
  - From / To / Reply-To / Return-Path
  - Subject and Message-ID
  - Authentication-Results
  - Plain-text and HTML bodies
  - Attachments and metadata
  - `Received:` mail-routing headers
  - URLs and IP addresses

### 2. Transparent Threat Detection
The threat detector uses explainable heuristic/rule-based signals rather than an opaque ML model. Signals include:

- Sender and Reply-To domain mismatches
- SPF, DKIM and DMARC failures/soft-failures
- Raw IP addresses used as URL hosts
- Suspicious top-level domains
- Lookalike/brand-impersonation domains
- Urgency and social-engineering language
- Business Email Compromise (BEC) / impersonation indicators
- Attachment-related checks

The result includes a classification, risk score, confidence value, and human-readable reasons.

### 3. SOC Investigation Dashboard
The prototype provides multiple views for security analysts:

- Dashboard
- Email checking and analysis
- Cases
- Alerts
- Investigation workspace
- IP geolocation
- Threat intelligence
- Live monitoring simulator
- PDF reports
- Help page

### 4. Forensic Timeline
`Received:` headers are reconstructed into a chronological mail-routing timeline showing:

- Hop number
- Source server
- Destination mail gateway
- IP address
- Timestamp
- Approximate delay
- Geographic information
- Risk flags

### 5. Threat Intelligence
The prototype includes a synthetic intelligence cache for demonstration data and optional external lookup integration points.

Supported intelligence concepts include:

- IP reputation
- Domain reputation
- URL reputation
- Threat categories
- ASN / ISP information
- Geographic information

> **Important:** Some intelligence displayed by the prototype is synthetic/demo data. It should not be treated as verified threat intelligence.

### 6. IP Geolocation
IP addresses can be mapped to:

- Country
- Region
- City
- Latitude / longitude
- ISP
- ASN
- Reputation/source information

The application contains demo IP data and can attempt a live `ip-api.com` lookup when the required network access is available.

### 7. Investigation Relationship Graph
The frontend supports interactive visualization of relationships between entities such as:

`Email → Sender → Domain → IP → Location / URL`

The prototype uses browser-side visualization libraries for this investigation experience.

### 8. PDF Forensic Reports
Analysts can generate PDF investigation reports containing:

- Case information
- Email metadata
- Threat classification
- Risk score
- Threat explanations
- SPF/DKIM/DMARC status
- Extracted IPs
- Geolocation information
- URLs/domains
- Timeline and investigation evidence
- Analyst notes

Reports are generated using **ReportLab**.

### 9. Multilingual User Experience
The frontend includes support for:

- English
- Telugu (తెలుగు)

---

## 🏗️ Architecture

```text
                    ┌──────────────────────────┐
                    │       Web Browser        │
                    │ HTML / CSS / JavaScript  │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │       Flask App           │
                    │         app.py            │
                    └────────────┬─────────────┘
                                 │
             ┌───────────────────┼───────────────────┐
             ▼                   ▼                   ▼
      ┌─────────────┐     ┌──────────────┐   ┌───────────────┐
      │ Email Parser│     │Threat Detector│   │ Threat Intel  │
      └──────┬──────┘     └──────┬───────┘   └───────┬───────┘
             │                   │                     │
             └───────────────────┼─────────────────────┘
                                 ▼
                    ┌──────────────────────────┐
                    │       SQLite Database    │
                    │ Cases / Emails / Alerts  │
                    │ Indicators / Notes       │
                    └────────────┬─────────────┘
                                 │
                    ┌────────────┴────────────┐
                    ▼                         ▼
             ┌──────────────┐        ┌────────────────┐
             │ Investigation│        │ PDF Report     │
             │ Timeline /   │        │ ReportLab      │
             │ Geo / Graph  │        └────────────────┘
             └──────────────┘
```

---

## 📁 Project Structure

```text
SIH-Prototype/
├── app.py
├── requirements.txt
├── .env.example
│
├── database/
│   ├── app_db.py
│   ├── schema.sql
│   └── app.db
│
├── services/
│   ├── email_parser.py
│   ├── geolocation.py
│   ├── report_generator.py
│   ├── threat_detector.py
│   ├── threat_intelligence.py
│   └── timeline.py
│
├── sample_emails/
│   ├── phishing.eml
│   ├── suspicious.eml
│   └── safe.eml
│
├── templates/
│   ├── alerts.html
│   ├── analysis_result.html
│   ├── base.html
│   ├── cases.html
│   ├── check_email.html
│   ├── dashboard.html
│   ├── geolocation.html
│   ├── help.html
│   ├── index.html
│   ├── intelligence.html
│   ├── investigation.html
│   ├── monitor.html
│   └── reports.html
│
└── static/
    ├── css/
    │   └── style.css
    ├── js/
    │   ├── dashboard.js
    │   ├── graph.js
    │   ├── main.js
    │   ├── monitor.js
    │   └── translations.js
    └── reports/
        └── generated PDF reports
```

---

## 🛠️ Technology Stack

| Layer | Technology |
|---|---|
| Backend | Python 3 |
| Web Framework | Flask |
| Database | SQLite |
| Email Parsing | Python `email` package |
| Threat Detection | Custom rule/heuristic engine |
| Frontend | HTML5, CSS3, JavaScript ES6 |
| PDF Generation | ReportLab |
| Maps | Leaflet.js |
| Relationship Graph | Cytoscape.js |
| Charts | Chart.js |
| Configuration | Environment variables / `.env` |

---

## 🚀 Quick Start

### Prerequisites

- Python **3.9+**
- `pip`
- A modern web browser

### 1. Extract the project

```bash
unzip SIH-Prototype.zip
cd SIH-Prototype
```

### 2. Create a virtual environment

#### Windows

```bash
python -m venv .venv
.venv\Scripts\activate
```

#### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure environment variables

Copy the example configuration:

```bash
cp .env.example .env
```

On Windows, copy the file manually if `cp` is unavailable.

Optional intelligence/API configuration can be added to `.env`, for example:

```env
SECRET_KEY=change-this-for-production
VT_API_KEY=your_virustotal_api_key
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
```

The prototype can still run without the external threat-intelligence API keys because it contains synthetic demonstration data and fallback responses.

### 5. Start the application

```bash
python app.py
```

### 6. Open the dashboard

Visit:

```text
http://127.0.0.1:5000
```

---

## 🧪 Demo Emails

Three synthetic `.eml` files are included:

| File | Purpose |
|---|---|
| `sample_emails/phishing.eml` | Demonstrates a high-risk phishing scenario |
| `sample_emails/suspicious.eml` | Demonstrates an impersonation/BEC-style scenario |
| `sample_emails/safe.eml` | Demonstrates a comparatively safe message |

You can upload these files from the **Check Email** page to demonstrate the complete workflow.

---

## 🔄 Typical Investigation Workflow

```text
1. Upload or paste an email
          ↓
2. Parse RFC 822 headers and message content
          ↓
3. Extract URLs, IPs, domains and attachments
          ↓
4. Evaluate authentication and behavioral indicators
          ↓
5. Calculate risk score and classification
          ↓
6. Create a forensic case
          ↓
7. Generate alerts for elevated-risk messages
          ↓
8. Investigate timeline, geolocation and intelligence
          ↓
9. Add analyst notes
          ↓
10. Generate/download PDF report
```

---

## 📊 Risk Classification

The prototype uses risk-score thresholds when creating cases:

| Risk Score | Priority |
|---:|---|
| `0–34` | Low |
| `35–69` | Medium |
| `70–100+` | High |

The score is generated from multiple heuristic indicators and can exceed the nominal 100-point scale internally before being handled by the application.

**Do not interpret the score as a calibrated probability of maliciousness.**

---

## 🔌 API / Application Endpoints

### Web Pages

```text
GET  /
GET  /dashboard
GET  /check
GET  /geolocation
GET  /cases
GET  /alerts
GET  /monitor
GET  /reports
GET  /intelligence
GET  /help
GET  /result/<case_number>
GET  /investigation/<case_number>
```

### Email Processing

```text
POST /upload
POST /paste
```

### Investigation

```text
POST /cases/<case_number>/notes
GET  /reports/download/<case_number>
```

### JSON Endpoints

```text
GET  /api/dashboard/stats
GET  /api/samples/<sample_type>
POST /api/monitor/trigger
```

The application contains additional API routes for the monitoring workflow.

---

## 🔐 Security & Privacy Notes

This is a **prototype for demonstration and hackathon evaluation**.

Before using a similar architecture in production:

- Do not expose the Flask development server directly to the public internet.
- Replace the default `SECRET_KEY`.
- Store API keys only in secure environment/configuration management.
- Validate and sanitize uploaded email content.
- Add authentication and role-based authorization.
- Apply CSRF protection to state-changing forms.
- Add rate limiting and upload quotas.
- Use a production WSGI server such as Gunicorn or Waitress.
- Review SSRF risks before enabling arbitrary URL lookups.
- Avoid executing or rendering untrusted email HTML without proper isolation.
- Treat email attachments as untrusted files.
- Protect generated reports and investigation data from unauthorized access.
- Replace synthetic threat-intelligence records with verified provider responses.
- Add structured logging, monitoring and audit trails.

---

## ⚠️ Prototype Limitations

1. **Heuristic detection:** The threat engine is rule-based and is not a trained AI/ML model.
2. **Synthetic intelligence:** Some IP/domain/URL intelligence is intentionally hard-coded for demonstration.
3. **External lookups:** Live geolocation/intelligence depends on network availability and configured services.
4. **No guaranteed verdict:** A risk score is an investigative aid, not proof that an email is malicious or legitimate.
5. **Demo database:** SQLite is suitable for the prototype but may not be appropriate for a multi-user production SOC.
6. **Email safety:** Uploaded emails should be treated as untrusted content.
7. **Generated reports:** PDF reports may contain sensitive email metadata and should be handled accordingly.

---

## 🧩 Database

The project uses SQLite and initializes its schema at application startup.

Main tables include:

- `users`
- `emails`
- `analysis_results`
- `indicators`
- `cases`
- `alerts`
- `timeline_events`
- `analyst_notes`
- `reports`

The schema is defined in:

```text
database/schema.sql
```

The application also seeds demonstration data when the database is empty.

---

## 📝 Development Notes

The core processing pipeline is intentionally modular:

- `services/email_parser.py` — parses email messages and extracts indicators.
- `services/threat_detector.py` — calculates threat signals and classifications.
- `services/threat_intelligence.py` — provides demo/external intelligence integration points.
- `services/geolocation.py` — resolves IP geolocation.
- `services/timeline.py` — builds forensic mail-routing timelines.
- `services/report_generator.py` — creates PDF investigation reports.
- `database/app_db.py` — handles SQLite database initialization and access.

This separation makes the prototype easier to extend with additional detection rules, intelligence providers, authentication mechanisms, and production data stores.

---

## 🎯 SIH Demonstration Highlights

For a hackathon presentation, the end-to-end demonstration can show:

1. Upload `phishing.eml`.
2. Display the generated threat classification and risk indicators.
3. Open the investigation case.
4. Show SPF/DKIM/DMARC findings.
5. Inspect extracted URLs and IP addresses.
6. Demonstrate the forensic timeline.
7. Display IP geolocation and threat intelligence.
8. Add an analyst note.
9. Generate the final PDF forensic report.
10. Trigger the monitoring simulator to demonstrate alert generation.

---

## 📄 License

No explicit open-source license is included in the supplied prototype. Unless a separate license is provided by the project owners, treat the source code as project-owned and obtain permission before redistributing it.

---

## 👥 Project

**EmailShield — SIH Prototype**

Built as a cybersecurity investigation and email-threat-analysis prototype for Smart India Hackathon.
