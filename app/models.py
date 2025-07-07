from datetime import datetime
from app import db
from flask_login import UserMixin

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), index=True, unique=True)
    email = db.Column(db.String(120), index=True, unique=True)
    password_hash = db.Column(db.String(128))
    scans = db.relationship('Scan', backref='author', lazy='dynamic')

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    target = db.Column(db.String(120))
    scan_type = db.Column(db.String(20))  # 'nmap', 'openvas', 'both'
    status = db.Column(db.String(20))  # 'queued', 'running', 'completed', 'failed'
    timestamp = db.Column(db.DateTime, index=True, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    results = db.relationship('ScanResult', backref='scan', lazy='dynamic')

class ScanResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'))
    result_type = db.Column(db.String(20))  # 'nmap', 'openvas'
    raw_data = db.Column(db.Text)
    critical_count = db.Column(db.Integer)
    high_count = db.Column(db.Integer)
    medium_count = db.Column(db.Integer)
    low_count = db.Column(db.Integer)
    info_count = db.Column(db.Integer)