# Risk Assessment Framework - Quick Start (3 Minutes)

## Prerequisites
- Python 3.8+ installed
- That's it! (No Node.js needed)

Verify Python:
```bash
python --version
```

## Step 1: Create Virtual Environment (30 seconds)

```bash
# Create and activate virtual environment
python -m venv venv

# Activate it:
# macOS/Linux:
source venv/bin/activate

# Windows:
venv\Scripts\activate

# You should see (venv) in your terminal
```

## Step 2: Install Flask (30 seconds)

```bash
# Make sure venv is activated (you see (venv) in terminal)
pip install -r requirements.txt

# That's it - just 2 packages: Flask and SQLAlchemy
```

## Step 3: Run the App (1 minute)

```bash
python app.py
```

You'll see:
```
============================================================
🚀 Risk Assessment Framework - Simple Flask Version
============================================================
📍 Running on http://localhost:5000
============================================================
```

## Step 4: Open in Browser

Go to: `http://localhost:5000`

**Done!** ✅ You now have a working risk assessment tool.

---

## What's Loaded by Default

- ✅ 6 IT assets (web server, database, payment gateway, email system, inventory, auth)
- ✅ 8 security threats (SQL injection, DDoS, phishing, ransomware, etc.)
- ✅ Ready to create risk assessments

---

## Using the App

### 📊 Dashboard
Shows summary of all risks:
- Total assessments
- Critical, High, Medium, Low counts
- Recent risk assessments

### 📦 Assets Tab
- View all registered IT assets
- Add new assets
- Delete assets

### 🔍 Assess Risk Tab
1. Select an asset (web server, database, etc.)
2. Select a threat (SQL injection, DDoS, etc.)
3. Rate **Likelihood** (1-5 scale)
4. Rate **Impact** (1-5 scale)
5. System calculates risk score automatically
6. Add remediation plan (optional)
7. Submit assessment

### 📈 Report Tab
- View all assessments sorted by risk score
- See risk matrix (Likelihood × Impact grid)
- View risk statistics

---

## Risk Scoring Explained

**Formula**: Risk Score = Likelihood × Impact

**Likelihood** (1-5):
- 1 = Rare (very unlikely)
- 2 = Unlikely
- 3 = Possible (50/50)
- 4 = Likely
- 5 = Almost Certain

**Impact** (1-5):
- 1 = Negligible (minor inconvenience)
- 2 = Minor (small financial loss)
- 3 = Moderate (significant impact)
- 4 = Major (serious impact, major loss)
- 5 = Catastrophic (business failure)

**Risk Levels**:
- **20-25**: 🔴 CRITICAL - Immediate action required
- **12-19**: 🟠 HIGH - Address within 2 weeks
- **6-11**: 🟡 MEDIUM - Plan remediation
- **1-5**: 🟢 LOW - Monitor regularly

---

## Example Assessment

Let's say you assess **Web Server** against **SQL Injection**:

```
Likelihood: 4/5 (SQL injection is common)
Impact: 5/5 (Full database exposure would be catastrophic)
Risk Score: 4 × 5 = 20
Risk Level: CRITICAL ⚠️
```

This risk needs immediate mitigation!

---

## Project Files

```
.
├── app.py                      ← Main Flask app (350 lines)
├── requirements.txt            ← Dependencies (2 packages)
├── README.md                   ← Full documentation
├── QUICKSTART.md              ← This file
├── static/
│   └── style.css              ← All styling
└── templates/
    ├── base.html              ← Navigation
    ├── index.html             ← Dashboard
    ├── assets.html            ← Asset list
    ├── add_asset.html         ← Asset form
    ├── assess.html            ← Assessment form
    ├── report.html            ← Risk report
    └── 404.html               ← Error page
```

---

## Stopping the App

Press `Ctrl+C` in the terminal

To deactivate virtual environment:
```bash
deactivate
```

---

## Troubleshooting

### "Python is not recognized"
- Make sure Python is installed
- Add Python to PATH (Windows: https://realpython.com/add-python-to-path/)

### "venv module not found"
```bash
# macOS/Linux (use python3):
python3 -m venv venv
source venv/bin/activate
```

### "Port 5000 already in use"
```bash
# Edit last line of app.py:
app.run(debug=True, port=5001)  # Use port 5001 instead
```

### "ModuleNotFoundError: flask"
```bash
# Make sure venv is activated (you see (venv) in terminal):
source venv/bin/activate  # macOS/Linux
venv\Scripts\activate     # Windows

# Then install:
pip install -r requirements.txt
```

### Database issues
```bash
# Delete database and restart:
rm instance/risk.db
python app.py
# It will auto-recreate with sample data
```

---

## Next Steps

### Learn the Code
1. Open `app.py` - it's well-commented
2. See `templates/` folder - simple HTML
3. Check `static/style.css` - responsive design

### Customize It
- **Add threats**: Edit `seed_database()` in app.py
- **Change colors**: Edit CSS variables in style.css
- **Change company**: Edit templates/base.html

### For Your Portfolio
- Add to GitHub
- Reference in resume
- Discuss in interviews
- Deploy to web (Heroku, Railway, PythonAnywhere)

### Expand It
- Add user login/authentication
- Generate PDF reports
- Add email notifications
- Track remediation progress
- Map to compliance frameworks

---

## Key Selling Points

✅ **Simple** - No JavaScript frameworks, just Flask and HTML
✅ **Fast** - Small codebase, quick to understand
✅ **Deployable** - Easy to host on any Python-friendly server
✅ **Professional** - Clean code, responsive design
✅ **Educational** - Great learning project for security knowledge

---

## What Happens When I Run It?

1. **Startup**:
   - Flask starts on port 5000
   - SQLite database creates in `instance/` folder
   - Sample data loads (6 assets, 8 threats)

2. **Browser**:
   - Opens dashboard showing summary
   - Shows 0 assessments initially
   - You can start creating assessments

3. **Database**:
   - Located at: `instance/risk.db`
   - Auto-created (SQLite is built into Python)
   - No setup needed

---

## Project Timeline

- **Startup**: 5 seconds
- **First page load**: 1 second
- **Creating assessment**: 2 seconds
- **Viewing report**: 1 second

It's fast because there's no build process or JavaScript bundling.

---

## For Your Cybersecurity Career

This project demonstrates:
- ✅ Risk assessment methodology (real-world used in security)
- ✅ Understanding of security frameworks (Likelihood × Impact)
- ✅ Full-stack web development
- ✅ Database design
- ✅ Professional code organization
- ✅ Security domain knowledge

Perfect for interviews or portfolio!

---

## Interview Answer Template

> "I built a Risk Assessment Framework using Flask to demonstrate how security professionals quantify and prioritize risks. The tool uses a Likelihood × Impact methodology to calculate risk scores from 1-25. 
>
> I chose Flask instead of a heavier framework because it's simple, fast, and shows I understand when to keep things lightweight. The entire codebase is about 350 lines of Python and 700 lines of CSS - very readable and maintainable.
>
> The tool comes pre-loaded with a realistic scenario of an e-commerce company with 6 assets and 8 different threats. You can assess any asset-threat combination and the system calculates the risk score automatically."

---

## Version Information

- **Flask**: 2.3.2
- **SQLAlchemy**: 3.0.5
- **Python**: 3.8+
- **Total Code**: ~1,050 lines (Python + HTML + CSS)

---

## Resources

- **Flask Docs**: https://flask.palletsprojects.com/
- **SQLAlchemy Docs**: https://docs.sqlalchemy.org/
- **Security+**: https://www.comptia.org/certifications/security
- **NIST Framework**: https://www.nist.gov/cyberframework

---

## Common Changes

### Add New Threat
In `app.py`, find `seed_database()`:
```python
threats_data = [
    ...
    ('Your Threat', 'Description', 'technical'),  # Add this line
]
```

### Add New Asset
Same location, add to `assets_data` list.

### Change Colors
In `static/style.css`, edit `:root` section at the top.

### Change Port
Last line of `app.py`:
```python
app.run(debug=True, port=8000)  # Change 5000 to 8000
```

---

## That's It!

You now have a fully functional cybersecurity risk assessment tool.

**It took 3 minutes to set up because it's that simple.**

No npm, no build process, no webpack. Just Python and Flask. 🐍

**Start using it**: `python app.py` then visit `http://localhost:5000`

Happy assessing! 🛡️
