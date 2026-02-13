"""
Risk Assessment Framework
A GRC tool for identifying, assessing, and managing cybersecurity risks
"""

from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'grc-risk-assessment-2024'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///risk.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

# ============================================================================
# DATABASE MODELS
# ============================================================================

# Association table for Risk Assessment <-> Compliance mapping
assessment_compliance = db.Table('assessment_compliance',
    db.Column('assessment_id', db.Integer, db.ForeignKey('risk_assessment.id'), primary_key=True),
    db.Column('compliance_id', db.Integer, db.ForeignKey('compliance_requirement.id'), primary_key=True)
)

class Asset(db.Model):
    """IT assets that need protection"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    asset_type = db.Column(db.String(50))  # Server, Database, Application, Network, Endpoint
    criticality = db.Column(db.String(20))  # Critical, High, Medium, Low
    owner = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    assessments = db.relationship('RiskAssessment', backref='asset', lazy=True, cascade='all, delete-orphan')

class Threat(db.Model):
    """Security threats that could affect assets"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(50))  # Technical, Human, Environmental, Process
    
    assessments = db.relationship('RiskAssessment', backref='threat', lazy=True)

class ComplianceRequirement(db.Model):
    """Regulatory compliance requirements"""
    id = db.Column(db.Integer, primary_key=True)
    regulation = db.Column(db.String(50), nullable=False)  # GDPR, HIPAA, PCI-DSS, SOC2
    requirement_id = db.Column(db.String(50))  # e.g., Article 32, Section 164.312
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))

class RiskAssessment(db.Model):
    """Individual risk assessments linking assets to threats"""
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    threat_id = db.Column(db.Integer, db.ForeignKey('threat.id'), nullable=False)
    likelihood = db.Column(db.Integer, nullable=False)  # 1-5
    impact = db.Column(db.Integer, nullable=False)  # 1-5
    risk_score = db.Column(db.Integer, nullable=False)  # likelihood * impact
    risk_level = db.Column(db.String(20))  # Critical, High, Medium, Low
    remediation_plan = db.Column(db.Text)
    remediation_status = db.Column(db.String(20), default='Open')  # Open, In Progress, Closed
    remediation_due_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    compliance_requirements = db.relationship('ComplianceRequirement', 
                                              secondary=assessment_compliance,
                                              backref=db.backref('assessments', lazy='dynamic'))

class Policy(db.Model):
    """Governance policies"""
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))  # Security, Privacy, Access Control, Incident Response
    version = db.Column(db.String(20), default='1.0')
    owner = db.Column(db.String(100))
    status = db.Column(db.String(20), default='Draft')  # Draft, Active, Under Review, Retired
    effective_date = db.Column(db.Date)
    review_date = db.Column(db.Date)
    content = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class AuditLog(db.Model):
    """Audit trail for accountability"""
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(50), nullable=False)  # Created, Updated, Deleted
    entity_type = db.Column(db.String(50), nullable=False)  # Asset, Assessment, Policy
    entity_id = db.Column(db.Integer)
    entity_name = db.Column(db.String(200))
    details = db.Column(db.Text)
    user = db.Column(db.String(100), default='System')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def calculate_risk_level(score):
    """Convert risk score to risk level"""
    if score >= 20:
        return 'Critical'
    elif score >= 12:
        return 'High'
    elif score >= 6:
        return 'Medium'
    else:
        return 'Low'

def log_action(action, entity_type, entity_id, entity_name, details=None):
    """Create audit log entry"""
    log = AuditLog(
        action=action,
        entity_type=entity_type,
        entity_id=entity_id,
        entity_name=entity_name,
        details=details
    )
    db.session.add(log)
    db.session.commit()

def init_sample_data():
    """Initialize database with sample data"""
    
    # Sample Assets
    assets = [
        Asset(name='Customer Database', description='PostgreSQL database containing customer PII', 
              asset_type='Database', criticality='Critical', owner='Database Team'),
        Asset(name='Web Application Server', description='Production web servers running customer portal',
              asset_type='Server', criticality='Critical', owner='DevOps Team'),
        Asset(name='Payment Gateway', description='Integration with payment processor',
              asset_type='Application', criticality='Critical', owner='Finance IT'),
        Asset(name='Email System', description='Corporate email and calendar system',
              asset_type='Application', criticality='High', owner='IT Operations'),
        Asset(name='Employee Workstations', description='End-user devices for staff',
              asset_type='Endpoint', criticality='Medium', owner='IT Support'),
        Asset(name='Internal Network', description='Corporate LAN and VPN infrastructure',
              asset_type='Network', criticality='High', owner='Network Team'),
    ]
    
    # Sample Threats
    threats = [
        Threat(name='SQL Injection', description='Malicious SQL queries to access/modify database',
               category='Technical'),
        Threat(name='Ransomware', description='Malware that encrypts data for ransom',
               category='Technical'),
        Threat(name='Phishing Attack', description='Social engineering to steal credentials',
               category='Human'),
        Threat(name='Weak Passwords', description='Easily guessable or compromised passwords',
               category='Human'),
        Threat(name='DDoS Attack', description='Distributed denial of service attack',
               category='Technical'),
        Threat(name='Insider Threat', description='Malicious or negligent employee actions',
               category='Human'),
        Threat(name='Unpatched Vulnerabilities', description='Known security flaws not remediated',
               category='Process'),
        Threat(name='Data Exfiltration', description='Unauthorized data transfer outside organization',
               category='Technical'),
    ]
    
    # Compliance Requirements
    compliance_reqs = [
        # GDPR
        ComplianceRequirement(regulation='GDPR', requirement_id='Article 32',
                              name='Security of Processing',
                              description='Implement appropriate technical and organizational measures',
                              category='Data Security'),
        ComplianceRequirement(regulation='GDPR', requirement_id='Article 33',
                              name='Breach Notification',
                              description='Notify supervisory authority within 72 hours of breach',
                              category='Incident Response'),
        ComplianceRequirement(regulation='GDPR', requirement_id='Article 25',
                              name='Data Protection by Design',
                              description='Implement data protection principles from the start',
                              category='Privacy'),
        ComplianceRequirement(regulation='GDPR', requirement_id='Article 35',
                              name='Data Protection Impact Assessment',
                              description='Assess impact of processing on data protection',
                              category='Risk Assessment'),
        # HIPAA
        ComplianceRequirement(regulation='HIPAA', requirement_id='164.312(a)',
                              name='Access Controls',
                              description='Implement technical policies for electronic PHI access',
                              category='Access Control'),
        ComplianceRequirement(regulation='HIPAA', requirement_id='164.312(c)',
                              name='Integrity Controls',
                              description='Protect electronic PHI from improper alteration',
                              category='Data Integrity'),
        ComplianceRequirement(regulation='HIPAA', requirement_id='164.308(a)(1)',
                              name='Security Management Process',
                              description='Implement policies to prevent, detect, contain violations',
                              category='Risk Management'),
        # PCI-DSS
        ComplianceRequirement(regulation='PCI-DSS', requirement_id='Req 1',
                              name='Install and Maintain Firewall',
                              description='Install and maintain network security controls',
                              category='Network Security'),
        ComplianceRequirement(regulation='PCI-DSS', requirement_id='Req 2',
                              name='Secure Configurations',
                              description='Apply secure configurations to all system components',
                              category='Configuration'),
        ComplianceRequirement(regulation='PCI-DSS', requirement_id='Req 3',
                              name='Protect Stored Account Data',
                              description='Protect stored account data with encryption',
                              category='Encryption'),
        ComplianceRequirement(regulation='PCI-DSS', requirement_id='Req 8',
                              name='Identify Users and Authenticate',
                              description='Identify and authenticate access to system components',
                              category='Access Control'),
    ]
    
    # Sample Policies
    policies = [
        Policy(name='Information Security Policy',
               description='Establishes the organization\'s approach to information security',
               category='Security', version='2.0', owner='CISO', status='Active',
               content='This policy defines requirements for protecting information assets...'),
        Policy(name='Acceptable Use Policy',
               description='Defines acceptable use of IT resources',
               category='Security', version='1.5', owner='IT Director', status='Active',
               content='All users must use IT resources responsibly...'),
        Policy(name='Data Classification Policy',
               description='Guidelines for classifying data based on sensitivity',
               category='Privacy', version='1.0', owner='Data Protection Officer', status='Active',
               content='Data shall be classified as Public, Internal, Confidential, or Restricted...'),
        Policy(name='Incident Response Policy',
               description='Procedures for responding to security incidents',
               category='Incident Response', version='3.0', owner='Security Team', status='Active',
               content='Security incidents must be reported within 1 hour of detection...'),
        Policy(name='Access Control Policy',
               description='Requirements for granting and managing access',
               category='Access Control', version='2.1', owner='IT Security', status='Active',
               content='Access shall be granted based on least privilege principle...'),
    ]
    
    for asset in assets:
        db.session.add(asset)
    for threat in threats:
        db.session.add(threat)
    for req in compliance_reqs:
        db.session.add(req)
    for policy in policies:
        db.session.add(policy)
    
    db.session.commit()
    
    # Create sample assessments
    sample_assessments = [
        {'asset': 'Customer Database', 'threat': 'SQL Injection', 'likelihood': 4, 'impact': 5,
         'remediation': 'Implement parameterized queries and input validation', 'status': 'In Progress'},
        {'asset': 'Customer Database', 'threat': 'Data Exfiltration', 'likelihood': 3, 'impact': 5,
         'remediation': 'Deploy DLP solution and enhance monitoring', 'status': 'Open'},
        {'asset': 'Email System', 'threat': 'Phishing Attack', 'likelihood': 4, 'impact': 3,
         'remediation': 'Implement email filtering and security awareness training', 'status': 'In Progress'},
        {'asset': 'Web Application Server', 'threat': 'DDoS Attack', 'likelihood': 3, 'impact': 4,
         'remediation': 'Implement CDN with DDoS protection', 'status': 'Open'},
        {'asset': 'Employee Workstations', 'threat': 'Ransomware', 'likelihood': 3, 'impact': 4,
         'remediation': 'Deploy EDR solution and improve backup strategy', 'status': 'Closed'},
        {'asset': 'Internal Network', 'threat': 'Unpatched Vulnerabilities', 'likelihood': 4, 'impact': 3,
         'remediation': 'Implement automated patch management', 'status': 'In Progress'},
        {'asset': 'Payment Gateway', 'threat': 'Weak Passwords', 'likelihood': 2, 'impact': 5,
         'remediation': 'Enforce MFA and password complexity requirements', 'status': 'Closed'},
        {'asset': 'Customer Database', 'threat': 'Insider Threat', 'likelihood': 2, 'impact': 5,
         'remediation': 'Implement privileged access management and monitoring', 'status': 'Open'},
    ]
    
    for sa in sample_assessments:
        asset = Asset.query.filter_by(name=sa['asset']).first()
        threat = Threat.query.filter_by(name=sa['threat']).first()
        score = sa['likelihood'] * sa['impact']
        assessment = RiskAssessment(
            asset_id=asset.id,
            threat_id=threat.id,
            likelihood=sa['likelihood'],
            impact=sa['impact'],
            risk_score=score,
            risk_level=calculate_risk_level(score),
            remediation_plan=sa['remediation'],
            remediation_status=sa['status']
        )
        db.session.add(assessment)
    
    db.session.commit()
    
    # Add compliance mappings
    sql_assessment = RiskAssessment.query.join(Threat).filter(Threat.name == 'SQL Injection').first()
    if sql_assessment:
        gdpr_32 = ComplianceRequirement.query.filter_by(requirement_id='Article 32').first()
        gdpr_33 = ComplianceRequirement.query.filter_by(requirement_id='Article 33').first()
        hipaa_access = ComplianceRequirement.query.filter_by(requirement_id='164.312(a)').first()
        pci_3 = ComplianceRequirement.query.filter_by(requirement_id='Req 3').first()
        if gdpr_32:
            sql_assessment.compliance_requirements.append(gdpr_32)
        if gdpr_33:
            sql_assessment.compliance_requirements.append(gdpr_33)
        if hipaa_access:
            sql_assessment.compliance_requirements.append(hipaa_access)
        if pci_3:
            sql_assessment.compliance_requirements.append(pci_3)
    
    db.session.commit()

# ============================================================================
# ROUTES - DASHBOARD
# ============================================================================

@app.route('/')
def index():
    """Main dashboard"""
    assessments = RiskAssessment.query.order_by(RiskAssessment.risk_score.desc()).all()
    
    # Statistics
    total_assessments = len(assessments)
    critical_count = sum(1 for a in assessments if a.risk_level == 'Critical')
    high_count = sum(1 for a in assessments if a.risk_level == 'High')
    medium_count = sum(1 for a in assessments if a.risk_level == 'Medium')
    low_count = sum(1 for a in assessments if a.risk_level == 'Low')
    
    # Remediation status
    open_count = sum(1 for a in assessments if a.remediation_status == 'Open')
    in_progress_count = sum(1 for a in assessments if a.remediation_status == 'In Progress')
    closed_count = sum(1 for a in assessments if a.remediation_status == 'Closed')
    
    # Recent assessments
    recent_assessments = RiskAssessment.query.order_by(RiskAssessment.created_at.desc()).limit(5).all()
    
    # Compliance summary
    compliance_reqs = ComplianceRequirement.query.all()
    affected_requirements = set()
    for assessment in assessments:
        for req in assessment.compliance_requirements:
            affected_requirements.add(req.id)
    
    return render_template('index.html',
                           total_assessments=total_assessments,
                           critical_count=critical_count,
                           high_count=high_count,
                           medium_count=medium_count,
                           low_count=low_count,
                           open_count=open_count,
                           in_progress_count=in_progress_count,
                           closed_count=closed_count,
                           recent_assessments=recent_assessments,
                           total_compliance=len(compliance_reqs),
                           affected_compliance=len(affected_requirements))

# ============================================================================
# ROUTES - ASSETS
# ============================================================================

@app.route('/assets')
def assets():
    """List all assets"""
    all_assets = Asset.query.order_by(Asset.criticality.desc()).all()
    return render_template('assets.html', assets=all_assets)

@app.route('/asset/add', methods=['GET', 'POST'])
def add_asset():
    """Add new asset"""
    if request.method == 'POST':
        asset = Asset(
            name=request.form['name'],
            description=request.form.get('description', ''),
            asset_type=request.form['asset_type'],
            criticality=request.form['criticality'],
            owner=request.form.get('owner', '')
        )
        db.session.add(asset)
        db.session.commit()
        log_action('Created', 'Asset', asset.id, asset.name)
        flash(f'Asset "{asset.name}" created successfully', 'success')
        return redirect(url_for('assets'))
    return render_template('add_asset.html')

@app.route('/asset/edit/<int:id>', methods=['GET', 'POST'])
def edit_asset(id):
    """Edit existing asset"""
    asset = Asset.query.get_or_404(id)
    if request.method == 'POST':
        asset.name = request.form['name']
        asset.description = request.form.get('description', '')
        asset.asset_type = request.form['asset_type']
        asset.criticality = request.form['criticality']
        asset.owner = request.form.get('owner', '')
        db.session.commit()
        log_action('Updated', 'Asset', asset.id, asset.name)
        flash(f'Asset "{asset.name}" updated successfully', 'success')
        return redirect(url_for('assets'))
    return render_template('edit_asset.html', asset=asset)

@app.route('/asset/delete/<int:id>')
def delete_asset(id):
    """Delete asset"""
    asset = Asset.query.get_or_404(id)
    name = asset.name
    db.session.delete(asset)
    db.session.commit()
    log_action('Deleted', 'Asset', id, name)
    flash(f'Asset "{name}" deleted', 'warning')
    return redirect(url_for('assets'))

# ============================================================================
# ROUTES - RISK ASSESSMENTS
# ============================================================================

@app.route('/assess', methods=['GET', 'POST'])
def assess():
    """Create new risk assessment"""
    if request.method == 'POST':
        likelihood = int(request.form['likelihood'])
        impact = int(request.form['impact'])
        score = likelihood * impact
        
        assessment = RiskAssessment(
            asset_id=int(request.form['asset_id']),
            threat_id=int(request.form['threat_id']),
            likelihood=likelihood,
            impact=impact,
            risk_score=score,
            risk_level=calculate_risk_level(score),
            remediation_plan=request.form.get('remediation_plan', ''),
            remediation_status=request.form.get('remediation_status', 'Open'),
            notes=request.form.get('notes', '')
        )
        db.session.add(assessment)
        db.session.commit()
        log_action('Created', 'Assessment', assessment.id, 
                   f'{assessment.asset.name} - {assessment.threat.name}')
        flash('Risk assessment created successfully', 'success')
        return redirect(url_for('report'))
    
    assets = Asset.query.order_by(Asset.name).all()
    threats = Threat.query.order_by(Threat.name).all()
    return render_template('assess.html', assets=assets, threats=threats)

@app.route('/assessment/edit/<int:id>', methods=['GET', 'POST'])
def edit_assessment(id):
    """Edit existing assessment"""
    assessment = RiskAssessment.query.get_or_404(id)
    if request.method == 'POST':
        assessment.likelihood = int(request.form['likelihood'])
        assessment.impact = int(request.form['impact'])
        assessment.risk_score = assessment.likelihood * assessment.impact
        assessment.risk_level = calculate_risk_level(assessment.risk_score)
        assessment.remediation_plan = request.form.get('remediation_plan', '')
        assessment.remediation_status = request.form.get('remediation_status', 'Open')
        assessment.notes = request.form.get('notes', '')
        db.session.commit()
        log_action('Updated', 'Assessment', assessment.id,
                   f'{assessment.asset.name} - {assessment.threat.name}')
        flash('Assessment updated successfully', 'success')
        return redirect(url_for('report'))
    
    assets = Asset.query.order_by(Asset.name).all()
    threats = Threat.query.order_by(Threat.name).all()
    return render_template('edit_assessment.html', assessment=assessment, 
                           assets=assets, threats=threats)

@app.route('/assessment/delete/<int:id>')
def delete_assessment(id):
    """Delete assessment"""
    assessment = RiskAssessment.query.get_or_404(id)
    name = f'{assessment.asset.name} - {assessment.threat.name}'
    db.session.delete(assessment)
    db.session.commit()
    log_action('Deleted', 'Assessment', id, name)
    flash('Assessment deleted', 'warning')
    return redirect(url_for('report'))

# ============================================================================
# ROUTES - COMPLIANCE
# ============================================================================

@app.route('/compliance')
def compliance():
    """Compliance overview"""
    requirements = ComplianceRequirement.query.order_by(
        ComplianceRequirement.regulation,
        ComplianceRequirement.requirement_id
    ).all()
    
    # Group by regulation
    regulations = {}
    for req in requirements:
        if req.regulation not in regulations:
            regulations[req.regulation] = []
        
        # Get assessments linked to this requirement
        linked_assessments = req.assessments.all()
        max_risk = max([a.risk_score for a in linked_assessments]) if linked_assessments else 0
        
        regulations[req.regulation].append({
            'requirement': req,
            'assessment_count': len(linked_assessments),
            'max_risk_score': max_risk,
            'max_risk_level': calculate_risk_level(max_risk) if max_risk > 0 else 'None'
        })
    
    return render_template('compliance_overview.html', regulations=regulations)

@app.route('/assessment/<int:id>/compliance', methods=['GET', 'POST'])
def assessment_compliance(id):
    """Manage compliance mappings for an assessment"""
    assessment = RiskAssessment.query.get_or_404(id)
    
    if request.method == 'POST':
        # Get selected compliance IDs
        selected_ids = request.form.getlist('compliance_ids')
        
        # Clear existing and add new mappings
        assessment.compliance_requirements = []
        for comp_id in selected_ids:
            req = ComplianceRequirement.query.get(int(comp_id))
            if req:
                assessment.compliance_requirements.append(req)
        
        db.session.commit()
        flash('Compliance mappings updated', 'success')
        return redirect(url_for('assessment_compliance', id=id))
    
    all_requirements = ComplianceRequirement.query.order_by(
        ComplianceRequirement.regulation,
        ComplianceRequirement.requirement_id
    ).all()
    
    # Get currently linked requirement IDs
    linked_ids = [r.id for r in assessment.compliance_requirements]
    
    return render_template('assessment_compliance.html', 
                           assessment=assessment,
                           requirements=all_requirements,
                           linked_ids=linked_ids)

@app.route('/assessment/<int:assessment_id>/compliance/remove/<int:compliance_id>')
def remove_compliance_mapping(assessment_id, compliance_id):
    """Remove a compliance mapping from an assessment"""
    assessment = RiskAssessment.query.get_or_404(assessment_id)
    requirement = ComplianceRequirement.query.get_or_404(compliance_id)
    
    if requirement in assessment.compliance_requirements:
        assessment.compliance_requirements.remove(requirement)
        db.session.commit()
        flash(f'Removed {requirement.regulation} {requirement.requirement_id} mapping', 'info')
    
    return redirect(url_for('assessment_compliance', id=assessment_id))

# ============================================================================
# ROUTES - POLICIES (GOVERNANCE)
# ============================================================================

@app.route('/policies')
def policies():
    """List all policies"""
    all_policies = Policy.query.order_by(Policy.category, Policy.name).all()
    return render_template('policies.html', policies=all_policies)

@app.route('/policy/add', methods=['GET', 'POST'])
def add_policy():
    """Add new policy"""
    if request.method == 'POST':
        policy = Policy(
            name=request.form['name'],
            description=request.form.get('description', ''),
            category=request.form['category'],
            version=request.form.get('version', '1.0'),
            owner=request.form.get('owner', ''),
            status=request.form.get('status', 'Draft'),
            content=request.form.get('content', '')
        )
        db.session.add(policy)
        db.session.commit()
        log_action('Created', 'Policy', policy.id, policy.name)
        flash(f'Policy "{policy.name}" created successfully', 'success')
        return redirect(url_for('policies'))
    return render_template('add_policy.html')

@app.route('/policy/view/<int:id>')
def view_policy(id):
    """View policy details"""
    policy = Policy.query.get_or_404(id)
    return render_template('view_policy.html', policy=policy)

@app.route('/policy/edit/<int:id>', methods=['GET', 'POST'])
def edit_policy(id):
    """Edit existing policy"""
    policy = Policy.query.get_or_404(id)
    if request.method == 'POST':
        policy.name = request.form['name']
        policy.description = request.form.get('description', '')
        policy.category = request.form['category']
        policy.version = request.form.get('version', '1.0')
        policy.owner = request.form.get('owner', '')
        policy.status = request.form.get('status', 'Draft')
        policy.content = request.form.get('content', '')
        db.session.commit()
        log_action('Updated', 'Policy', policy.id, policy.name)
        flash(f'Policy "{policy.name}" updated successfully', 'success')
        return redirect(url_for('policies'))
    return render_template('edit_policy.html', policy=policy)

@app.route('/policy/delete/<int:id>')
def delete_policy(id):
    """Delete policy"""
    policy = Policy.query.get_or_404(id)
    name = policy.name
    db.session.delete(policy)
    db.session.commit()
    log_action('Deleted', 'Policy', id, name)
    flash(f'Policy "{name}" deleted', 'warning')
    return redirect(url_for('policies'))

# ============================================================================
# ROUTES - REPORT
# ============================================================================

@app.route('/report')
def report():
    """Detailed risk report"""
    assessments = RiskAssessment.query.order_by(RiskAssessment.risk_score.desc()).all()
    
    # Build risk matrix data
    risk_matrix = [[0 for _ in range(5)] for _ in range(5)]
    for assessment in assessments:
        row = 5 - assessment.impact  # Invert for display (high impact at top)
        col = assessment.likelihood - 1
        risk_matrix[row][col] += 1
    
    return render_template('report.html', 
                           assessments=assessments,
                           risk_matrix=risk_matrix)

# ============================================================================
# ROUTES - AUDIT LOG
# ============================================================================

@app.route('/audit')
def audit_log():
    """View audit trail"""
    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(100).all()
    return render_template('audit_log.html', logs=logs)

# ============================================================================
# ROUTES - THREATS
# ============================================================================

@app.route('/threats')
def threats():
    """List all threats"""
    all_threats = Threat.query.order_by(Threat.category, Threat.name).all()
    return render_template('threats.html', threats=all_threats)

@app.route('/threat/add', methods=['GET', 'POST'])
def add_threat():
    """Add new threat"""
    if request.method == 'POST':
        threat = Threat(
            name=request.form['name'],
            description=request.form.get('description', ''),
            category=request.form['category']
        )
        db.session.add(threat)
        db.session.commit()
        log_action('Created', 'Threat', threat.id, threat.name)
        flash(f'Threat "{threat.name}" created successfully', 'success')
        return redirect(url_for('threats'))
    return render_template('add_threat.html')

@app.route('/threat/delete/<int:id>')
def delete_threat(id):
    """Delete threat"""
    threat = Threat.query.get_or_404(id)
    name = threat.name
    db.session.delete(threat)
    db.session.commit()
    log_action('Deleted', 'Threat', id, name)
    flash(f'Threat "{name}" deleted', 'warning')
    return redirect(url_for('threats'))

# ============================================================================
# ERROR HANDLERS
# ============================================================================

@app.errorhandler(404)
def not_found(e):
    return render_template('404.html'), 404

# ============================================================================
# MAIN
# ============================================================================

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        # Initialize sample data if database is empty
        if Asset.query.count() == 0:
            init_sample_data()
            print("✓ Sample data initialized")
    
    print("\n" + "="*50)
    print("  GRC Risk Assessment Framework")
    print("  http://localhost:5000")
    print("="*50 + "\n")
    
    app.run(debug=True, port=5000)
