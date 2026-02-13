# GRC Risk Assessment Framework

A comprehensive Governance, Risk, and Compliance (GRC) tool built with Python Flask that helps organizations identify, assess, and manage cybersecurity risks.

## 🎯 Key Features

### Risk Management
- **Asset Management** — Track IT infrastructure (servers, databases, applications, networks)
- **Threat Catalog** — Maintain a library of security threats
- **Risk Assessment** — Evaluate threats using Likelihood × Impact methodology (1-25 scale)
- **Risk Matrix** — Visual heatmap showing risk distribution
- **Remediation Tracking** — Track open, in-progress, and closed remediation efforts

### Compliance
- **Regulatory Mapping** — Link risks to GDPR, HIPAA, PCI-DSS requirements
- **Compliance Overview** — See which regulations are affected by identified risks
- **Requirement Tracking** — Monitor 11 pre-loaded compliance requirements

### Governance
- **Policy Management** — Create and manage organizational policies
- **Policy Categories** — Security, Privacy, Access Control, Incident Response
- **Version Control** — Track policy versions and ownership
- **Policy Lifecycle** — Draft → Under Review → Active → Retired

### Audit & Accountability
- **Audit Log** — Automatic tracking of all create, update, delete actions
- **Timestamps** — Full audit trail for compliance evidence
- **User Attribution** — Track who made changes

## 📊 Risk Scoring

```
Risk Score = Likelihood (1-5) × Impact (1-5)

Levels:
- 20-25: CRITICAL (fix immediately)
- 12-19: HIGH (fix within 2 weeks)  
- 6-11:  MEDIUM (plan remediation)
- 1-5:   LOW (monitor)
```

## 🛠️ Tech Stack

- **Python 3.8+**
- **Flask** — Web framework
- **Flask-SQLAlchemy** — Database ORM
- **SQLite** — Database
- **HTML/CSS** — Frontend (no JavaScript frameworks required)

## 🚀 Quick Start

### 1. Clone or Download
```bash
mkdir risk-assessment && cd risk-assessment
# Copy all project files here
```

### 2. Create Virtual Environment
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the Application
```bash
python app.py
```

### 5. Open in Browser
Visit `http://localhost:5000`

The app loads with sample data:
- 6 IT assets
- 8 security threats
- 11 compliance requirements (GDPR, HIPAA, PCI-DSS)
- 5 governance policies
- 8 sample risk assessments

## 📁 Project Structure

```
risk-assessment/
├── app.py                          # Main Flask application
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── static/
│   └── style.css                  # Complete styling
├── templates/
│   ├── base.html                  # Navigation & layout
│   ├── index.html                 # Dashboard
│   ├── assets.html                # Asset list
│   ├── add_asset.html             # Add asset form
│   ├── edit_asset.html            # Edit asset form
│   ├── threats.html               # Threat catalog
│   ├── add_threat.html            # Add threat form
│   ├── assess.html                # Risk assessment form
│   ├── edit_assessment.html       # Edit assessment form
│   ├── report.html                # Risk report with matrix
│   ├── compliance_overview.html   # Compliance dashboard
│   ├── assessment_compliance.html # Map risks to compliance
│   ├── policies.html              # Policy list
│   ├── add_policy.html            # Add policy form
│   ├── edit_policy.html           # Edit policy form
│   ├── view_policy.html           # Policy detail view
│   ├── audit_log.html             # Audit trail
│   └── 404.html                   # Error page
└── instance/
    └── risk.db                    # SQLite database (auto-created)
```

## 🔗 Routes

### Dashboard
- `GET /` — Main dashboard with summary statistics

### Assets
- `GET /assets` — List all assets
- `GET /asset/add` — Add asset form
- `POST /asset/add` — Create asset
- `GET /asset/edit/<id>` — Edit asset form
- `POST /asset/edit/<id>` — Update asset
- `GET /asset/delete/<id>` — Delete asset

### Threats
- `GET /threats` — Threat catalog
- `GET /threat/add` — Add threat form
- `POST /threat/add` — Create threat
- `GET /threat/delete/<id>` — Delete threat

### Risk Assessments
- `GET /assess` — Assessment form
- `POST /assessment/add` — Create assessment
- `GET /assessment/edit/<id>` — Edit assessment form
- `POST /assessment/edit/<id>` — Update assessment
- `GET /assessment/delete/<id>` — Delete assessment
- `GET /report` — Detailed risk report

### Compliance
- `GET /compliance` — Compliance overview
- `GET /assessment/<id>/compliance` — View/manage compliance mappings
- `POST /assessment/<id>/compliance` — Update compliance mappings
- `GET /assessment/<id>/compliance/remove/<compliance_id>` — Remove mapping

### Governance
- `GET /policies` — Policy list
- `GET /policy/add` — Add policy form
- `POST /policy/add` — Create policy
- `GET /policy/view/<id>` — View policy details
- `GET /policy/edit/<id>` — Edit policy form
- `POST /policy/edit/<id>` — Update policy
- `GET /policy/delete/<id>` — Delete policy

### Audit
- `GET /audit` — View audit log

## 💼 Portfolio Demonstration

This project demonstrates skills in:

1. **GRC Framework Understanding**
   - Risk assessment methodology
   - Compliance mapping
   - Policy lifecycle management

2. **Web Development**
   - Python Flask backend
   - SQLAlchemy ORM
   - Responsive HTML/CSS frontend

3. **Database Design**
   - Relational data modeling
   - Many-to-many relationships
   - Audit logging

4. **Security Concepts**
   - Threat categorization
   - Risk quantification
   - Regulatory requirements (GDPR, HIPAA, PCI-DSS)

## 📈 Extending the Project

Ideas for enhancement:
- Add user authentication
- Export reports to PDF
- Email notifications for overdue remediations
- Risk trend charts over time
- API endpoints for integration
- Role-based access control
- Document attachment support

## 📄 License

MIT License — Free for personal and commercial use.

---

Built as a portfolio project demonstrating GRC knowledge and full-stack development skills.
