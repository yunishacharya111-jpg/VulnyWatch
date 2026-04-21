from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

from flask_login import UserMixin

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    email_verified = db.Column(db.Boolean, default=False)
    scans = db.relationship('Scan', backref='user', lazy=True)

class Scan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    url = db.Column(db.String(300), nullable=False)
    score = db.Column(db.Integer, default=0)
    risk_label = db.Column(db.String(50), default='Unknown')
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    results = db.relationship('Result', backref='scan', lazy=True)

class Result(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.id'), nullable=False)
    check_name = db.Column(db.String(100))
    status = db.Column(db.String(20))
    severity = db.Column(db.String(20))
    detail = db.Column(db.Text)
    owasp = db.Column(db.String(50))
    fix = db.Column(db.Text)