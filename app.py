"""
Risk Assessment Framework - Simple Flask Version
A lightweight cybersecurity risk assessment tool with compliance mapping
"""

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
import os

# Create instance folder if it doesn't exist
basedir = os.path.abspath(os.path.dirname(__file__))
instance_folder = os.path.join(basedir, 'instance')
if not os.path.exists(instance_folder):
    os.makedirs(instance_folder)

# Initialize Flask app
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{os.path.join(instance_folder, "risk.db")}'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'dev-secret-key-change-in-production'

# Initialize database
db = SQLAlchemy(app)

# ==================== DATABASE MODELS ====================

class Asset(db.Model):
    """IT Asset to protect"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    asset_type = db.Column(db.String(50), nullable=False)
    criticality = db.Column(db.String(20), default='medium')
    owner = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    assessments = db.relationship('Assessment', backref='asset', lazy=True, cascade='all, delete-orphan')


class Threat(db.Model):
    """Security threat"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)


class Compliance(db.Model):
    """Compliance requirement (GDPR, HIPAA, PCI-DSS, etc.)"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    description = db.Column(db.Text)
    requirement = db.Column(db.Text)
    category = db.Column(db.String(50), nullable=False)
    
    def to_dict(self):
        return {
            'id': self.id,
            'name': self.name,
            'description': self.description,
            'requirement': self.requirement,
            'category': self.category
        }


class AssessmentCompliance(db.Model):
    """Link assessments to compliance requirements"""
    __tablename__ = 'assessment_compliance'
    
    id = db.Column(db.Integer, primary_key=True)
    assessment_id = db.Column(db.Integer, db.ForeignKey('assessment.id'), nullable=False)
    compliance_id = db.Column(db.Integer, db.ForeignKey('compliance.id'), nullable=False)
    
    assessment = db.relationship('Assessment', backref='compliance_reqs')
    compliance = db.relationship('Compliance', backref='assessments')


class Assessment(db.Model):
    """Risk assessment - combines asset, threat, and scoring"""
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey('threat.id'), nullable=False)
    
    likelihood = db.Column(db.Integer, nullable=False)  # 1-5
    impact = db.Column(db.Integer, nullable=False)      # 1-5
    risk_score = db.Column(db.Integer)                  # Calculated
    risk_level = db.Column(db.String(20))               # Critical, High, Medium, Low
    
    remediation_plan = db.Column(db.Text)
    remediation_status = db.Column(db.String(20), default='not_started')
    
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    threat = db.relationship('Threat', backref='assessments')
    
    def calculate_risk(self):
        """Calculate risk score and level"""
        self.risk_score = self.likelihood * self.impact
        
        if self.risk_score >= 20:
            self.risk_level = 'critical'
        elif self.risk_score >= 12:
            self.risk_level = 'high'
        elif self.risk_score >= 6:
            self.risk_level = 'medium'
        else:
            self.risk_level = 'low'


# ==================== HELPER FUNCTIONS ====================

def seed_database():
    """Populate database with sample data"""
    if Asset.query.first() is not None:
        return  # Already seeded
    
    # Sample assets
    assets_data = [
        ('Web Application Server', 'Main e-commerce website', 'server', 'critical', 'DevOps Team'),
        ('Customer Database', 'PostgreSQL with customer data', 'database', 'critical', 'Database Admin'),
        ('Payment Gateway', 'Stripe/PayPal integration', 'payment', 'critical', 'Finance'),
        ('Email System', 'Customer communications', 'application', 'high', 'Marketing'),
        ('Inventory System', 'Stock management', 'application', 'high', 'Operations'),
        ('Auth System', 'Login and authentication', 'application', 'critical', 'Security'),
    ]
    
    for name, desc, atype, crit, owner in assets_data:
        asset = Asset(name=name, description=desc, asset_type=atype, 
                     criticality=crit, owner=owner)
        db.session.add(asset)
    
    # Sample threats
    threats_data = [
        ('SQL Injection', 'Attacker injects SQL code to access database', 'technical'),
        ('DDoS Attack', 'Overwhelming servers with traffic', 'technical'),
        ('Data Breach', 'Unauthorized access to customer data', 'technical'),
        ('Phishing Attack', 'Social engineering to steal credentials', 'human'),
        ('Ransomware', 'Malware encrypting systems and demanding payment', 'technical'),
        ('Weak Passwords', 'Inadequate password policies', 'human'),
        ('Unpatched Systems', 'Failure to apply security updates', 'technical'),
        ('Payment Fraud', 'Stolen credit card data misuse', 'technical'),
    ]
    
    for name, desc, cat in threats_data:
        threat = Threat(name=name, description=desc, category=cat)
        db.session.add(threat)
    
    # Sample compliance requirements
    compliance_data = [
        # GDPR
        ('GDPR Article 5', 'Data Protection', 'Personal data must be processed lawfully, fairly and transparently', 'GDPR'),
        ('GDPR Article 32', 'Data Security', 'Implement appropriate technical and organisational security measures', 'GDPR'),
        ('GDPR Article 33', 'Breach Notification', 'Notify authorities of data breach within 72 hours', 'GDPR'),
        
        # HIPAA
        ('HIPAA Security Rule', 'Access Controls', 'Implement access controls and audit controls for patient data', 'HIPAA'),
        ('HIPAA Breach Rule', 'Breach Notification', 'Notify individuals if unsecured PHI is breached', 'HIPAA'),
        ('HIPAA Privacy Rule', 'Data Privacy', 'Protect patient privacy and confidentiality', 'HIPAA'),
        
        # PCI-DSS
        ('PCI-DSS 1', 'Firewall', 'Install and maintain firewall configuration', 'PCI-DSS'),
        ('PCI-DSS 2', 'Passwords', 'Do not use default passwords', 'PCI-DSS'),
        ('PCI-DSS 3', 'Encryption', 'Protect stored cardholder data', 'PCI-DSS'),
        ('PCI-DSS 4', 'Encryption Transit', 'Render PAN unreadable during transmission', 'PCI-DSS'),
        ('PCI-DSS 6', 'Secure Code', 'Develop and maintain secure systems', 'PCI-DSS'),
    ]
    
    for name, req, desc, cat in compliance_data:
        compliance = Compliance(name=name, requirement=req, description=desc, category=cat)
        db.session.add(compliance)
    
    db.session.commit()
    print("✓ Database seeded with sample data")


# ==================== ROUTES ====================

@app.route('/')
def index():
    """Dashboard - show summary and recent assessments"""
    assessments = Assessment.query.order_by(Assessment.risk_score.desc()).all()
    
    # Calculate summary
    summary = {
        'total': len(assessments),
        'critical': len([a for a in assessments if a.risk_level == 'critical']),
        'high': len([a for a in assessments if a.risk_level == 'high']),
        'medium': len([a for a in assessments if a.risk_level == 'medium']),
        'low': len([a for a in assessments if a.risk_level == 'low']),
    }
    
    return render_template('index.html', 
                         assessments=assessments[:10],
                         summary=summary)


@app.route('/assets')
def assets():
    """List all assets"""
    assets = Asset.query.all()
    return render_template('assets.html', assets=assets)


@app.route('/asset/add', methods=['GET', 'POST'])
def add_asset():
    """Add new asset"""
    if request.method == 'POST':
        # Check if asset already exists
        if Asset.query.filter_by(name=request.form['name']).first():
            flash('Asset with this name already exists!', 'error')
            return redirect(url_for('add_asset'))
        
        asset = Asset(
            name=request.form['name'],
            description=request.form['description'],
            asset_type=request.form['asset_type'],
            criticality=request.form['criticality'],
            owner=request.form['owner']
        )
        db.session.add(asset)
        db.session.commit()
        flash(f'Asset "{asset.name}" added successfully!', 'success')
        return redirect(url_for('assets'))
    
    return render_template('add_asset.html')


@app.route('/asset/delete/<int:asset_id>')
def delete_asset(asset_id):
    """Delete asset"""
    asset = Asset.query.get_or_404(asset_id)
    name = asset.name
    db.session.delete(asset)
    db.session.commit()
    flash(f'Asset "{name}" deleted!', 'success')
    return redirect(url_for('assets'))


@app.route('/assess')
def assess():
    """Risk assessment form"""
    assets = Asset.query.all()
    threats = Threat.query.all()
    return render_template('assess.html', assets=assets, threats=threats)


@app.route('/assessment/add', methods=['POST'])
def add_assessment():
    """Create new assessment"""
    asset_id = request.form.get('asset_id')
    threat_id = request.form.get('threat_id')
    
    # Check if already exists
    existing = Assessment.query.filter_by(asset_id=asset_id, threat_id=threat_id).first()
    if existing:
        flash('Assessment already exists for this asset-threat pair!', 'error')
        return redirect(url_for('assess'))
    
    assessment = Assessment(
        asset_id=int(asset_id),
        threat_id=int(threat_id),
        likelihood=int(request.form['likelihood']),
        impact=int(request.form['impact']),
        remediation_plan=request.form.get('remediation_plan', ''),
    )
    
    assessment.calculate_risk()
    db.session.add(assessment)
    db.session.commit()
    
    flash(f'Risk assessment created! Score: {assessment.risk_score} ({assessment.risk_level.upper()})', 'success')
    return redirect(url_for('index'))


@app.route('/assessment/delete/<int:assessment_id>')
def delete_assessment(assessment_id):
    """Delete assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)
    db.session.delete(assessment)
    db.session.commit()
    flash('Assessment deleted!', 'success')
    return redirect(url_for('index'))


@app.route('/report')
def report():
    """Detailed risk report"""
    assessments = Assessment.query.order_by(Assessment.risk_score.desc()).all()
    
    # Build risk matrix data
    matrix = {}
    for i in range(1, 6):
        for j in range(1, 6):
            matrix[f'{i}_{j}'] = []
    
    for a in assessments:
        key = f'{a.likelihood}_{a.impact}'
        if key in matrix:
            matrix[key].append(a)
    
    return render_template('report.html', assessments=assessments, matrix=matrix)


# ==================== COMPLIANCE ROUTES ====================

@app.route('/assessment/<int:assessment_id>/compliance', methods=['GET', 'POST'])
def assessment_compliance(assessment_id):
    """Add compliance requirements to an assessment"""
    assessment = Assessment.query.get_or_404(assessment_id)
    compliances = Compliance.query.all()
    
    if request.method == 'POST':
        compliance_id = request.form.get('compliance_id')
        
        # Check if already linked
        existing = AssessmentCompliance.query.filter_by(
            assessment_id=assessment_id,
            compliance_id=compliance_id
        ).first()
        
        if existing:
            flash('Compliance requirement already linked!', 'error')
        else:
            link = AssessmentCompliance(assessment_id=assessment_id, compliance_id=compliance_id)
            db.session.add(link)
            db.session.commit()
            flash('Compliance requirement added!', 'success')
        
        return redirect(url_for('assessment_compliance', assessment_id=assessment_id))
    
    return render_template('assessment_compliance.html', 
                         assessment=assessment, 
                         compliances=compliances)


@app.route('/assessment/<int:assessment_id>/compliance/remove/<int:compliance_id>')
def remove_compliance(assessment_id, compliance_id):
    """Remove compliance link from assessment"""
    link = AssessmentCompliance.query.filter_by(
        assessment_id=assessment_id,
        compliance_id=compliance_id
    ).first_or_404()
    
    db.session.delete(link)
    db.session.commit()
    flash('Compliance requirement removed!', 'success')
    return redirect(url_for('assessment_compliance', assessment_id=assessment_id))


@app.route('/compliance')
def compliance_overview():
    """Show all compliance requirements and affected assessments"""
    compliances = Compliance.query.all()
    
    compliance_data = []
    for comp in compliances:
        affected_assessments = AssessmentCompliance.query.filter_by(compliance_id=comp.id).all()
        compliance_data.append({
            'compliance': comp,
            'risk_count': len(affected_assessments),
            'risks': [ac for ac in affected_assessments]
        })
    
    return render_template('compliance_overview.html', compliance_data=compliance_data)


@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template('404.html'), 404


# ==================== CREATE TABLES & RUN ====================

if __name__ == '__main__':
    with app.app_context():
        try:
            db.create_all()
            seed_database()
            print("✓ Database tables created successfully")
        except Exception as e:
            print(f"Error creating database: {e}")
            print("Trying to continue anyway...")
    
    print("=" * 60)
    print("🚀 Risk Assessment Framework - Simple Flask Version")
    print("=" * 60)
    print("📍 Running on http://localhost:5000")
    print("=" * 60)
    
    app.run(debug=True, port=5000)