import os
import threading
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from itsdangerous import URLSafeTimedSerializer
from database import db, User, Scan, Result

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vulnywatch-secret-key-2026')

# Database configuration - PostgreSQL or SQLite fallback
DATABASE_URL = os.environ.get('DATABASE_URL')
if DATABASE_URL and DATABASE_URL.startswith('postgres'):
    app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URL.replace('postgres://', 'postgresql://')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/vulnywatch.db'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

SENDGRID_API_KEY = os.environ.get('SENDGRID_API_KEY')
SENDER_EMAIL = 'yunishacharya111@gmail.com'

db.init_app(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

def generate_verification_token(email):
    s = URLSafeTimedSerializer(app.secret_key)
    return s.dumps(email, salt='email-verify')

def verify_token(token, expiration=3600):
    s = URLSafeTimedSerializer(app.secret_key)
    try:
        email = s.loads(token, salt='email-verify', max_age=expiration)
    except:
        return None
    return email

def send_email(to_email, subject, html_content):
    message = Mail(
        from_email=SENDER_EMAIL,
        to_emails=to_email,
        subject=subject,
        html_content=html_content
    )
    try:
        sg = SendGridAPIClient(SENDGRID_API_KEY)
        sg.send(message)
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/contact')
def contact():
    return render_template('contact.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name     = request.form['name']
        email    = request.form['email']
        password = request.form['password']
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            return redirect(url_for('register'))
        hashed = generate_password_hash(password)
        user   = User(name=name, email=email, password=hashed, email_verified=False)
        db.session.add(user)
        db.session.commit()
        token = generate_verification_token(email)
        verify_url = url_for('verify_email', token=token, _external=True)
        send_email(email, 'Verify your VulnyWatch account', f'''
        <div style="font-family:sans-serif;max-width:500px;margin:auto;">
          <h2 style="color:#238636;">Welcome to VulnyWatch!</h2>
          <p>Click the button below to verify your email:</p>
          <a href="{verify_url}" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;margin:16px 0;">Verify Email</a>
          <p style="color:#888;">This link expires in 1 hour.</p>
        </div>''')
        flash('Account created! Please check your email to verify your account.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/verify/<token>')
def verify_email(token):
    email = verify_token(token)
    if email is None:
        flash('The verification link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    user = User.query.filter_by(email=email).first()
    if user is None:
        flash('User not found.', 'error')
        return redirect(url_for('login'))
    if user.email_verified:
        flash('Email already verified. Please log in.', 'success')
        return redirect(url_for('login'))
    user.email_verified = True
    db.session.commit()
    flash('Email verified! You can now log in.', 'success')
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email    = request.form['email']
        password = request.form['password']
        remember = request.form.get('remember')
        user     = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                flash('Please verify your email before logging in. Check your inbox.', 'error')
                return redirect(url_for('login'))
            login_user(user, remember=remember == 'on')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'error')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.timestamp.desc()).all()
    return render_template('dashboard.html', scans=scans)

@app.route('/scan', methods=['POST'])
@login_required
def scan():
    from scanner import run_scan
    
    url = request.form['url'].strip()
    if not url.startswith('http'):
        url = 'https://' + url
    
    # Create scan record with Pending status
    new_scan = Scan(user_id=current_user.id, url=url, score=0, risk_label='Pending')
    db.session.add(new_scan)
    db.session.commit()
    
    # Run scan in background thread
    def run_scan_background(scan_id, target_url):
        with app.app_context():
            scan = db.session.get(Scan, scan_id)
            try:
                scan.risk_label = 'Connectivity'
                db.session.commit()
                
                scan_results, score, label = run_scan(target_url)
                
                scan.risk_label = 'Reporting'
                db.session.commit()
                
                scan.score = score
                scan.risk_label = label
                for r in scan_results:
                    db.session.add(Result(
                        scan_id=scan_id,
                        check_name=r['check_name'],
                        status=r['status'],
                        severity=r['severity'],
                        detail=r['detail'],
                        owasp=r['owasp'],
                        fix=r['fix']
                    ))
                db.session.commit()
                
            except Exception as e:
                print(f"[SCAN ERROR] {e}")
                scan.risk_label = 'Error'
                db.session.commit()
    
    # Start background thread
    thread = threading.Thread(target=run_scan_background, args=(new_scan.id, url))
    thread.start()
    
    # Redirect to progress page
    return redirect(url_for('scan_progress', scan_id=new_scan.id))

@app.route('/scan-progress')
@login_required
def scan_progress():
    scan_id = request.args.get('scan_id')
    if not scan_id:
        return redirect(url_for('dashboard'))
    return render_template('scan_progress.html', scan_id=scan_id)

@app.route('/get-scan-url/<int:scan_id>')
@login_required
def get_scan_url(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan and scan.user_id == current_user.id:
        return {'url': scan.url}
    return {'url': 'Unknown'}

@app.route('/scan-status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return {'status': 'error', 'message': 'Unauthorized'}
    
    # Progress mapping
    progress_map = {
        'Pending': (5, 0, 'Initializing scanner...'),
        'Connectivity': (15, 1, 'Checking website connectivity...'),
        'SSL': (30, 2, 'Analyzing SSL/TLS security...'),
        'Headers': (50, 3, 'Checking security headers...'),
        'Injection': (65, 4, 'Testing for injection vulnerabilities...'),
        'AccessControl': (80, 5, 'Checking access control issues...'),
        'Reporting': (90, 6, 'Generating security report...'),
    }
    
    risk_label = scan.risk_label
    
    if risk_label in progress_map:
        percent, step, text = progress_map[risk_label]
        return {
            'status': 'scanning',
            'progress_percent': percent,
            'step_index': step,
            'current_step': text
        }
    elif risk_label in ['SECURE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']:
        return {
            'status': 'completed',
            'progress_percent': 100,
            'step_index': 6,
            'current_step': 'Scan complete!'
        }
    elif risk_label == 'Error':
        return {
            'status': 'error',
            'progress_percent': 0,
            'step_index': 0,
            'current_step': 'Scan failed'
        }
    
    return {
        'status': 'scanning',
        'progress_percent': 10,
        'step_index': 0,
        'current_step': 'Starting scan...'
    }

@app.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    scan_results = Result.query.filter_by(scan_id=scan_id).all()
    return render_template('results.html', scan=scan, results=scan_results)

@app.route('/resend-verification', methods=['GET', 'POST'])
def resend_verification():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user and not user.email_verified:
            token = generate_verification_token(email)
            verify_url = url_for('verify_email', token=token, _external=True)
            send_email(email, 'Verify your VulnyWatch account', f'''
            <div style="font-family:sans-serif;max-width:500px;margin:auto;">
              <h2 style="color:#238636;">Verify your VulnyWatch account</h2>
              <p>Click the button below to verify your email:</p>
              <a href="{verify_url}" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;margin:16px 0;">Verify Email</a>
              <p style="color:#888;">This link expires in 1 hour.</p>
            </div>''')
        flash('If that email exists and is unverified, we sent a new link.', 'success')
        return redirect(url_for('login'))
    return render_template('resend_verification.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email=email).first()
        if user:
            token = generate_verification_token(email)
            reset_url = url_for('reset_password', token=token, _external=True)
            send_email(email, 'Reset your VulnyWatch password', f'''
            <div style="font-family:sans-serif;max-width:500px;margin:auto;">
              <h2 style="color:#238636;">Reset your password</h2>
              <p>Click the button below to reset your password:</p>
              <a href="{reset_url}" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;margin:16px 0;">Reset Password</a>
              <p style="color:#888;">This link expires in 1 hour.</p>
            </div>''')
        flash('If that email exists, we sent a password reset link.', 'success')
        return redirect(url_for('login'))
    return render_template('forgot_password.html')

@app.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    email = verify_token(token)
    if email is None:
        flash('The reset link is invalid or has expired.', 'error')
        return redirect(url_for('login'))
    if request.method == 'POST':
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = generate_password_hash(password)
            db.session.commit()
            flash('Password reset successfully! Please log in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_password.html')

@app.route('/delete-scan/<int:scan_id>', methods=['POST'])
@login_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return 'Unauthorized', 403
    
    Result.query.filter_by(scan_id=scan_id).delete()
    db.session.delete(scan)
    db.session.commit()
    return 'OK', 200

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)