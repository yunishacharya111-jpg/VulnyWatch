import os
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer
from database import db, User, Scan, Result

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'vulnywatch-secret-key-2024')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:////tmp/vulnywatch.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = os.environ.get('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('MAIL_USERNAME')

db.init_app(app)
mail = Mail(app)

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

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/')
def index():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    return render_template('index.html')

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
        msg = Message('Verify your VulnyWatch account', recipients=[email])
        msg.html = f'''
        <div style="font-family:sans-serif;max-width:500px;margin:auto;">
          <h2 style="color:#238636;">Welcome to VulnyWatch!</h2>
          <p>Click the button below to verify your email:</p>
          <a href="{verify_url}" style="background:#238636;color:#fff;padding:12px 24px;border-radius:6px;text-decoration:none;display:inline-block;margin:16px 0;">Verify Email</a>
          <p style="color:#888;">This link expires in 1 hour.</p>
        </div>'''
        try:
            mail.send(msg)
            flash('Account created! Please check your email to verify your account.', 'success')
        except Exception as e:
            print(f"[EMAIL ERROR] {e}")
            flash('Account created but verification email failed. Please contact support.', 'error')
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
        user     = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            if not user.email_verified:
                flash('Please verify your email before logging in. Check your inbox.', 'error')
                return redirect(url_for('login'))
            login_user(user)
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
    new_scan = Scan(user_id=current_user.id, url=url, score=0, risk_label='Pending')
    db.session.add(new_scan)
    db.session.commit()
    try:
        scan_results, score, label = run_scan(url)
        new_scan.score      = score
        new_scan.risk_label = label
        for r in scan_results:
            db.session.add(Result(
                scan_id    = new_scan.id,
                check_name = r['check_name'],
                status     = r['status'],
                severity   = r['severity'],
                detail     = r['detail'],
                owasp      = r['owasp'],
                fix        = r['fix']
            ))
        db.session.commit()
    except Exception as e:
        print(f"[SCAN ERROR] {e}")
        new_scan.risk_label = 'Error'
        db.session.commit()
    return redirect(url_for('results', scan_id=new_scan.id))

@app.route('/results/<int:scan_id>')
@login_required
def results(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None or scan.user_id != current_user.id:
        return redirect(url_for('dashboard'))
    scan_results = Result.query.filter_by(scan_id=scan_id).all()
    return render_template('results.html', scan=scan, results=scan_results)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)