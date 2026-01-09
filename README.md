# Risk Assessment Framework
A lightweight cybersecurity risk assessment tool that helps organizations:
- Identify and prioritize security risks
- 🎯 Quantify risks using Likelihood × Impact methodology
- 📋 Map risks to compliance requirements
- 📈 Track security posture over time
## Key Features

**Asset Management** - Add and track IT infrastructure
**Risk Assessment** - Evaluate threats using Likelihood × Impact scoring
**Risk Dashboard** - View summary statistics and recent assessments
**Compliance Mapping** - Link risks to GDPR, HIPAA, PCI-DSS requirements
**Compliance Overview** - See which regulations are affected by which risks
**Risk Report** - Detailed analysis with risk matrix visualization
**Simple & Fast** - No build process, no npm, just Python

## Tech Stack
- **Python 3.8+**
- **Flask** - Web framework
- **SQLAlchemy** - Database ORM
- **SQLite** - Database
- **HTML/CSS** - Frontend

## Quick Start

### 1. Setup (2 minutes)

```bash
# Create project directory
mkdir risk-assessment && cd risk-assessment

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Run (1 minute)

```bash
# Activate virtual environment (if not already)
source venv/bin/activate  # Windows: venv\Scripts\activate

# Start the app
python app.py
```

Visit `http://localhost:5000` in your browser

### Done! 
The app loads with:
- 6 IT assets
- 8 security threats
- 11 compliance requirements (GDPR, HIPAA, PCI-DSS)
- Sample assessments ready to explore

## Usage Workflow

### 1. Dashboard
View all risks at a glance:
- Total assessments count
- Critical/High/Medium/Low breakdown
- Recent risk assessments
- Compliance status overview

### 2. Manage Assets 
Add/delete IT infrastructure:
- Web servers
- Databases
- Payment gateways
- Applications
- Email systems

### 3. Create Risk Assessment 
Evaluate threats:
1. Select asset (e.g., Database)
2. Select threat (e.g., SQL Injection)
3. Rate likelihood (1-5)
4. Rate impact (1-5)
5. Risk score auto-calculates
6. Add remediation plan

### 4. Map to Compliance 
Link risks to regulations:
1. Click "Compliance" on assessment
2. Select which regulations are affected
3. View all linked requirements

### 5. View Compliance Overview 
See regulatory landscape:
- All compliance requirements
- Which risks affect each regulation
- Affected risk scores
- Category breakdown (GDPR/HIPAA/PCI-DSS)

### 6. View Report 
Detailed risk analysis:
- All assessments sorted by risk
- Risk matrix visualization
- Risk statistics

## Risk Formula
```
Risk Score = Likelihood (1-5) × Impact (1-5)

Scoring:
- 20-25: CRITICAL (fix immediately)
- 12-19: HIGH (fix within 2 weeks)
- 6-11:  MEDIUM (plan remediation)
- 1-5:   LOW (monitor)
```

## Project Structure
```
.
├── app.py                          # Main Flask app (450+ lines)
├── requirements.txt                # Python dependencies
├── README.md                       # This file
├── QUICKSTART.md                   # Quick setup guide
├── static/
│   └── style.css                  # Complete styling (700+ lines)
├── templates/
│   ├── base.html                  # Navigation & layout
│   ├── index.html                 # Dashboard (with compliance)
│   ├── assets.html                # Asset list
│   ├── add_asset.html             # Asset form
│   ├── assess.html                # Assessment form
│   ├── report.html                # Risk report
│   ├── assessment_compliance.html  # Map compliance to risk
│   ├── compliance_overview.html    # View all compliance reqs
│   └── 404.html                   # Error page
└── instance/
    └── risk.db                    # SQLite database (auto-created)
```

## Routes

### Main Routes
- `GET /` - Dashboard with summary
- `GET /assets` - List all assets
- `GET /asset/add` - Add asset form
- `POST /asset/add` - Create asset
- `GET /asset/delete/<id>` - Delete asset
- `GET /assess` - Assessment form
- `POST /assessment/add` - Create assessment
- `GET /assessment/delete/<id>` - Delete assessment
- `GET /report` - Detailed risk report

### Compliance Routes (NEW)
- `GET /compliance` - Compliance overview
- `GET /assessment/<id>/compliance` - View compliance mappings
- `POST /assessment/<id>/compliance` - Add compliance mapping
- `GET /assessment/<id>/compliance/remove/<compliance_id>` - Remove mapping

## Example: SQL Injection Risk
```
Asset: Customer Database (Critical)
Threat: SQL Injection (Technical)

Assessment:
- Likelihood: 4/5 (Attackers target databases)
- Impact: 5/5 (Complete data exposure)
- Risk Score: 4 × 5 = 20
- Risk Level: CRITICAL ⚠️

Compliance Affected:
✓ GDPR Article 32 - Data Security
✓ GDPR Article 33 - Breach Notification
✓ HIPAA Security Rule - Access Controls
✓ PCI-DSS 3 - Encryption

Action: Fix immediately - violates multiple regulations
```

## Example: Weak Passwords
```
Asset: Email System (High)
Threat: Weak Passwords (Human)

Assessment:
- Likelihood: 3/5 (Common)
- Impact: 2/5 (Limited access)
- Risk Score: 3 × 2 = 6
- Risk Level: MEDIUM 🟡

Compliance Affected:
✓ PCI-DSS 2 - Passwords
✓ HIPAA Security Rule - Access Controls

Action: Train employees on password policy