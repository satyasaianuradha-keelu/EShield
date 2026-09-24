# EmailShield

### AI-Powered Email Threat Detection, Geolocation and Forensic Intelligence Platform

> **Tagline**: *Detect. Investigate. Stay Safe.*

EmailShield is an evidence-centric email investigation platform built for both non-technical users and professional SOC security analysts. It converts complex raw email headers and RFC822 metadata into simple explainable risk alerts, interactive forensic timelines, relationship network graphs, IP geolocation maps, and downloadable PDF investigation reports.

---

## Key Features

1. **Dual Persona Interface**:
   - **Normal User Mode**: Simple color-coded threat result, clear explanations ("Why is this risky?"), and actionable advice ("What should you do?"). Supports **English** and **Telugu (తెలుగు)**.
   - **Analyst Mode**: Professional SOC investigation hub with 8 detailed tabs (Overview, Headers, Authentication, URLs & Domains, IP & Geolocation, Timeline, Graph, PDF Report).

2. **Transparent AI & Rule Engine**:
   - Multi-signal transparent threat detection (Sender mismatch, SPF/DKIM/DMARC failure indicators, suspicious lookalike URLs, urgency social engineering language, BEC/impersonation markers, attachment safety checks).

3. **Forensic Intelligence & Visualizations**:
   - **IP Geolocation Map**: Leaflet.js interactive map plotting sender & mail relay server hops.
   - **Forensic Timeline**: Chronological reconstruction of `Received:` header hops with anomaly flags.
   - **Investigation Relationship Graph**: Cytoscape.js interactive network mapping `Email → Sender → Domain → IP → Location / URLs`.

4. **Live Email Monitoring Simulator**:
   - Simulated inbox environment to demonstrate real-time email ingestion, automated threat classification, and toast security alerts.

5. **PDF Investigation Report Generator**:
   - ReportLab powered executive SOC PDF export with full case evidence, indicators of compromise (IOCs), and analyst notes.

---

## Quick Start Guide

### Prerequisites
- Python 3.9+
- `pip` package manager

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Run Application
```bash
python app.py
```

### 3. Access Application
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## Synthetic Sample Demonstration

The platform comes pre-seeded with 3 synthetic test emails for demonstration:
1. **PayPal Urgency Phishing** (`phishing.eml`): High risk credential harvester with SPF failure and fake domain.
2. **Executive BEC Impersonation** (`suspicious.eml`): Spoofed CEO request with domain mismatch.
3. **Legitimate Corporate Update** (`safe.eml`): Verified internal communication.

---

## Technology Stack

- **Backend**: Python 3, Flask, SQLite3
- **Frontend**: HTML5, CSS3 (Custom Dark/Light SOC Design System), JavaScript (ES6)
- **Visualizations**: Chart.js, Leaflet.js, Cytoscape.js
- **PDF Engine**: ReportLab
