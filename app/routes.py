# app/routes.py

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from app.models import SystemUser, Application, Scan, Credential, URL, Violation, Report
from app import db, oauth
from datetime import datetime
import re
import os
import smtplib
import ssl
import secrets
import time
from itsdangerous import URLSafeTimedSerializer, BadSignature, SignatureExpired

# Initialize the blueprint
main = Blueprint('main', __name__)

def _infer_dvwa_security_level(label: str | None) -> str | None:
    """
    Best-effort helper to infer DVWA security level from an application/profile label.
    Examples:
      "DVWA | Impossible Security" -> "impossible"
      "DVWA | Low Security" -> "low"
    """
    if not label:
        return None

    lowered = label.lower()
    if "dvwa" not in lowered:
        return None

    for level in ("impossible", "high", "medium", "low"):
        if level in lowered:
            return level

    return None

def _get_serializer():
    secret = os.getenv('SECRET_KEY', 'your_secret_key')
    return URLSafeTimedSerializer(secret, salt='password-reset')

def _send_email(to_email, subject, body):
    host = os.getenv('SMTP_HOST')
    port = int(os.getenv('SMTP_PORT', '587'))
    username = os.getenv('SMTP_USERNAME')
    password = os.getenv('SMTP_PASSWORD')
    use_tls = os.getenv('SMTP_USE_TLS', '1') == '1'

    if not host or not username or not password:
        return False

    message = f"Subject: {subject}\nTo: {to_email}\nFrom: {username}\n\n{body}"
    context = ssl.create_default_context()

    try:
        with smtplib.SMTP(host, port, timeout=10) as server:
            if use_tls:
                server.starttls(context=context)
            server.login(username, password)
            server.sendmail(username, [to_email], message)
        return True
    except Exception as e:
        print("Email send error:", e)
        return False

def _generate_verification_code():
    return f"{secrets.randbelow(1000000):06d}"

def _oauth_configured(provider):
    if provider == 'google':
        client_id = os.getenv('GOOGLE_CLIENT_ID', '')
        client_secret = os.getenv('GOOGLE_CLIENT_SECRET', '')
    elif provider == 'github':
        client_id = os.getenv('GITHUB_CLIENT_ID', '')
        client_secret = os.getenv('GITHUB_CLIENT_SECRET', '')
    else:
        return False

    if not client_id or not client_secret:
        return False

    placeholder_markers = ['your_', 'placeholder']
    lower_id = client_id.lower()
    lower_secret = client_secret.lower()
    if any(marker in lower_id for marker in placeholder_markers):
        return False
    if any(marker in lower_secret for marker in placeholder_markers):
        return False

    return True

# -------------------------------------------------------
# Home Route
# -------------------------------------------------------
@main.route('/')
def home():
    if "username" in session:
        return redirect(url_for('main.dashboard'))
    return render_template('index.html')


# -------------------------------------------------------
# Login Route
# -------------------------------------------------------
@main.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        # Fetch user from database
        user = SystemUser.query.filter_by(username=username).first()

        # Validate user credentials
        if user and check_password_hash(user.password_hash, password):
            session['username'] = username
            session['user_id'] = user.user_id
            return redirect(url_for('main.dashboard'))
        else:
            return render_template(
                'login.html',
                error='Invalid credentials',
                google_oauth_enabled=_oauth_configured('google'),
                github_oauth_enabled=_oauth_configured('github')
            )

    return render_template(
        'login.html',
        google_oauth_enabled=_oauth_configured('google'),
        github_oauth_enabled=_oauth_configured('github')
    )

# -------------------------------------------------------
# Forgot Password
# -------------------------------------------------------
@main.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    message = None
    reset_link = None

    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        if not email:
            message = 'Please enter your email address.'
        else:
            user = SystemUser.query.filter_by(email=email).first()
            if user:
                serializer = _get_serializer()
                token = serializer.dumps(user.email)
                reset_link = url_for('main.reset_password', token=token, _external=True)
                sent = _send_email(
                    user.email,
                    'Reset your Perimeter password',
                    f'Click the link to reset your password:\n\n{reset_link}\n\nThis link expires in 1 hour.'
                )
                message = 'If the email exists, a reset link has been sent.'
                if not sent:
                    message = 'Email delivery is not configured. Use the link below to reset your password.'
            else:
                message = 'If the email exists, a reset link has been sent.'

    return render_template('forgot_password.html', message=message, reset_link=reset_link)


# -------------------------------------------------------
# Reset Password
# -------------------------------------------------------
@main.route('/reset-password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    message = None
    error = None

    try:
        serializer = _get_serializer()
        email = serializer.loads(token, max_age=3600)
    except SignatureExpired:
        error = 'This reset link has expired. Please request a new one.'
        return render_template('reset_password.html', error=error, token=None)
    except BadSignature:
        error = 'Invalid reset link.'
        return render_template('reset_password.html', error=error, token=None)

    if request.method == 'POST':
        password = request.form.get('password', '')
        confirm = request.form.get('confirm_password', '')
        if not password or not confirm:
            error = 'Please fill in all fields.'
        elif password != confirm:
            error = 'Passwords do not match.'
        elif len(password) < 8:
            error = 'Password must be at least 8 characters.'
        else:
            user = SystemUser.query.filter_by(email=email).first()
            if not user:
                error = 'User not found.'
            else:
                user.password_hash = generate_password_hash(password)
                db.session.commit()
                message = 'Password updated successfully. You can now sign in.'

    return render_template('reset_password.html', message=message, error=error, token=token)

# -------------------------------------------------------
# Login API (POST)
# -------------------------------------------------------
@main.route('/api/login', methods=['POST'])
def login_post():
    try:
        data = request.get_json()

        email = data.get('email')
        password = data.get('password')

        if not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400

        # Check if user exists
        user = SystemUser.query.filter_by(email=email).first()
        if not user:
            return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401

        # Verify password
        if not check_password_hash(user.password_hash, password):
            return jsonify({'success': False, 'message': 'Invalid email or password.'}), 401

        # Store session info
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role

        # Redirect user to dashboard (or homepage)
        return jsonify({
            'success': True,
            'message': f'Welcome back, {user.username}!',
            'username': user.username,
            'redirect_url': url_for('main.dashboard')  # change if your dashboard route name differs
        }), 200

    except Exception as e:
        print("Login error:", e)
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500


# -------------------------------------------------------
# Signup Page
# -------------------------------------------------------
@main.route('/signup')
def signup():
    return render_template(
        'signup.html',
        google_oauth_enabled=_oauth_configured('google'),
        github_oauth_enabled=_oauth_configured('github')
    )


# -------------------------------------------------------
# Signup API (POST)
# -------------------------------------------------------
@main.route('/api/signup', methods=['POST'])
def signup_post():
    try:
        data = request.get_json()

        username = data.get('username')
        email = data.get('email')
        password = data.get('password')

        # Check for missing fields
        if not username or not email or not password:
            return jsonify({'success': False, 'message': 'All fields are required.'}), 400

        # Validate email format
        if not re.match(r'^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$', email or ''):
            return jsonify({'success': False, 'message': 'Please enter a valid email address.'}), 400

        # Check if user already exists
        existing_user = SystemUser.query.filter(
            (SystemUser.username == username) | (SystemUser.email == email)
        ).first()
        if existing_user:
            return jsonify({'success': False, 'message': 'Username or email already exists.'}), 400

        # Hash password and start email verification
        hashed_password = generate_password_hash(password)
        verification_code = _generate_verification_code()

        session['signup_pending'] = {
            'username': username,
            'email': email,
            'password_hash': hashed_password
        }
        session['signup_code'] = verification_code
        session['signup_code_sent_at'] = time.time()

        sent = _send_email(
            email,
            'Verify your Perimeter account',
            f'Hi {username},\n\nYour verification code is: {verification_code}\n\n'
            'Enter this code to finish creating your account. This code expires in 10 minutes.'
        )

        if not sent:
            session.pop('signup_pending', None)
            session.pop('signup_code', None)
            session.pop('signup_code_sent_at', None)
            return jsonify({
                'success': False,
                'message': 'Email delivery is not configured. Please contact support.'
            }), 503

        return jsonify({
            'success': True,
            'message': 'Verification code sent to your email.',
            'verification_required': True
        }), 200

    except Exception as e:
        print("Signup error:", e)
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500


# -------------------------------------------------------
# Signup Verification API (POST)
# -------------------------------------------------------
@main.route('/api/signup/verify', methods=['POST'])
def signup_verify():
    try:
        data = request.get_json()
        code = (data.get('code') or '').strip()

        pending = session.get('signup_pending')
        expected_code = session.get('signup_code')
        sent_at = session.get('signup_code_sent_at')

        if not pending or not expected_code or not sent_at:
            return jsonify({'success': False, 'message': 'No pending signup found. Please start again.'}), 400

        if not code:
            return jsonify({'success': False, 'message': 'Verification code is required.'}), 400

        if time.time() - float(sent_at) > 600:
            session.pop('signup_pending', None)
            session.pop('signup_code', None)
            session.pop('signup_code_sent_at', None)
            return jsonify({'success': False, 'message': 'Verification code expired. Please sign up again.'}), 400

        if code != expected_code:
            return jsonify({'success': False, 'message': 'Invalid verification code.'}), 400

        # Ensure email/username are still unique
        existing_user = SystemUser.query.filter(
            (SystemUser.username == pending['username']) | (SystemUser.email == pending['email'])
        ).first()
        if existing_user:
            session.pop('signup_pending', None)
            session.pop('signup_code', None)
            session.pop('signup_code_sent_at', None)
            return jsonify({'success': False, 'message': 'Username or email already exists.'}), 400

        new_user = SystemUser(
            username=pending['username'],
            email=pending['email'],
            password_hash=pending['password_hash'],
            role="user",
            created_at=datetime.utcnow()
        )

        db.session.add(new_user)
        db.session.commit()

        session.pop('signup_pending', None)
        session.pop('signup_code', None)
        session.pop('signup_code_sent_at', None)

        _send_email(
            new_user.email,
            'Welcome to Perimeter',
            f'Hi {new_user.username},\n\nYour account has been created successfully.\n\n- Perimeter Team'
        )

        return jsonify({
            'success': True,
            'message': 'Email verified. Account created.',
            'redirect_url': url_for('main.login')
        }), 201

    except Exception as e:
        print("Signup verification error:", e)
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500


# -------------------------------------------------------
# Email Check API
# -------------------------------------------------------
# @main.route('/api/check-email', methods=['POST'])
# def check_email():
#     try:
#         data = request.get_json()
#         email = data.get('email')

#         exists = User.query.filter_by(email=email).first() is not None

#         return jsonify({'exists': exists})

#     except Exception as e:
#         return jsonify({'error': str(e)}), 500


# -------------------------------------------------------
# Google OAuth Routes
# -------------------------------------------------------
@main.route('/oauth/google')
def google_login():
    """Initiate Google OAuth login flow."""
    if not _oauth_configured('google'):
        flash('Google OAuth is not configured. Please update .env credentials.', 'error')
        return redirect(url_for('main.login'))
    redirect_uri = url_for('main.google_callback', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)


@main.route('/oauth/google/callback')
def google_callback():
    """Handle Google OAuth callback."""
    try:
        token = oauth.google.authorize_access_token()
        user_info = token.get('userinfo')
        
        if not user_info:
            # Fetch user info from Google
            resp = oauth.google.get('https://openidconnect.googleapis.com/v1/userinfo')
            user_info = resp.json()
        
        email = user_info.get('email')
        name = user_info.get('name', email.split('@')[0])
        google_id = user_info.get('sub')
        
        if not email:
            flash('Could not get email from Google', 'error')
            return redirect(url_for('main.login'))
        
        # Check if user exists with this email
        user = SystemUser.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if not set
            if not user.oauth_provider:
                user.oauth_provider = 'google'
                user.oauth_id = google_id
                db.session.commit()
        else:
            # Create new user
            # Generate unique username from name or email
            base_username = name.replace(' ', '_').lower()[:40]
            username = base_username
            counter = 1
            while SystemUser.query.filter_by(username=username).first():
                username = f"{base_username}_{counter}"
                counter += 1
            
            user = SystemUser(
                username=username,
                email=email,
                password_hash=None,  # OAuth users don't need password
                role='user',
                oauth_provider='google',
                oauth_id=google_id,
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
        
        # Set session
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        session['full_name'] = name or ''
        
        return redirect(url_for('main.dashboard') + '?login_success=true&user=' + user.username)
    
    except Exception as e:
        print(f"Google OAuth error: {e}")
        flash('Google login failed. Please try again.', 'error')
        return redirect(url_for('main.login'))


# -------------------------------------------------------
# GitHub OAuth Routes
# -------------------------------------------------------
@main.route('/oauth/github')
def github_login():
    """Initiate GitHub OAuth login flow."""
    if not _oauth_configured('github'):
        flash('GitHub OAuth is not configured. Please update .env credentials.', 'error')
        return redirect(url_for('main.login'))
    redirect_uri = url_for('main.github_callback', _external=True)
    return oauth.github.authorize_redirect(redirect_uri)


@main.route('/oauth/github/callback')
def github_callback():
    """Handle GitHub OAuth callback."""
    try:
        token = oauth.github.authorize_access_token()
        
        # Fetch user info from GitHub API
        resp = oauth.github.get('user')
        user_info = resp.json()
        
        github_id = str(user_info.get('id'))
        name = user_info.get('name') or user_info.get('login')
        
        # GitHub doesn't always return email in profile, need to fetch separately
        email = user_info.get('email')
        if not email:
            # Fetch emails from GitHub
            emails_resp = oauth.github.get('user/emails')
            emails = emails_resp.json()
            # Get primary verified email
            for e in emails:
                if e.get('primary') and e.get('verified'):
                    email = e.get('email')
                    break
            # Fallback to first email
            if not email and emails:
                email = emails[0].get('email')
        
        if not email:
            flash('Could not get email from GitHub. Please ensure your email is public or verified.', 'error')
            return redirect(url_for('main.login'))
        
        # Check if user exists with this email
        user = SystemUser.query.filter_by(email=email).first()
        
        if user:
            # Update OAuth info if not set
            if not user.oauth_provider:
                user.oauth_provider = 'github'
                user.oauth_id = github_id
                db.session.commit()
        else:
            # Create new user
            # Generate unique username from GitHub login or name
            base_username = (user_info.get('login') or name.replace(' ', '_').lower())[:40]
            username = base_username
            counter = 1
            while SystemUser.query.filter_by(username=username).first():
                username = f"{base_username}_{counter}"
                counter += 1
            
            user = SystemUser(
                username=username,
                email=email,
                password_hash=None,  # OAuth users don't need password
                role='user',
                oauth_provider='github',
                oauth_id=github_id,
                created_at=datetime.utcnow()
            )
            db.session.add(user)
            db.session.commit()
        
        # Set session
        session['user_id'] = user.user_id
        session['username'] = user.username
        session['role'] = user.role
        session['full_name'] = name or ''
        
        return redirect(url_for('main.dashboard') + '?login_success=true&user=' + user.username)
    
    except Exception as e:
        print(f"GitHub OAuth error: {e}")
        flash('GitHub login failed. Please try again.', 'error')
        return redirect(url_for('main.login'))


# -------------------------------------------------------
# Dashboard Route
# -------------------------------------------------------
@main.route('/dashboard')
def dashboard():
    # ✅ Check if logged in
    if 'user_id' not in session:
        return redirect(url_for('main.login'))

    # ✅ Get user from session
    user_id = session['user_id']
    user = SystemUser.query.get(user_id)

    if not user:
        # In case session exists but user is deleted
        session.clear()
        return redirect(url_for('main.login'))

    # ✅ Fetch recent scans (limit 5 for dashboard table)
    scans = (
        Scan.query.filter_by(user_id=user.user_id)
        .order_by(Scan.created_at.desc())
        .limit(5)
        .all()
    )

    # ✅ Count all scans
    total_scans = Scan.query.filter_by(user_id=user.user_id).count()
    
    # ✅ Get all user scan IDs for computing totals
    all_user_scans = Scan.query.filter_by(user_id=user.user_id).all()
    all_scan_ids = [s.scan_id for s in all_user_scans]
    
    # ✅ Total vulnerabilities across ALL scans
    total_vulns = sum(getattr(scan, 'vulnerable_count', 0) or 0 for scan in all_user_scans)
    
    # ✅ Total URLs crawled across all scans
    total_urls = 0
    if all_scan_ids:
        total_urls = URL.query.filter(URL.scan_id.in_(all_scan_ids)).count()
    
    # ✅ Get unique roles tested from credentials
    user_apps = Application.query.filter_by(user_id=user.user_id).all()
    app_ids = [app.app_id for app in user_apps]
    total_roles = 0
    if app_ids:
        total_roles = db.session.query(db.func.count(db.distinct(Credential.role_name))).filter(
            Credential.app_id.in_(app_ids)
        ).scalar() or 0
    
    # ✅ Get latest scan for risk assessment
    latest_scan = scans[0] if scans else None
    risk_data = {
        'risk_percent': 0,
        'risk_level': 'low',
        'critical_count': 0,
        'high_count': 0,
        'medium_count': 0,
        'description': 'No scans completed yet.'
    }
    
    if latest_scan and latest_scan.status == 'Completed':
        # Get violations from latest scan
        latest_urls = URL.query.filter_by(scan_id=latest_scan.scan_id).all()
        latest_url_ids = [u.url_id for u in latest_urls]
        
        if latest_url_ids:
            # Count violations by type (simulate severity levels)
            violations = Violation.query.filter(Violation.url_id.in_(latest_url_ids)).all()
            
            # Categorize by violation_type (simplified categorization)
            for v in violations:
                vtype = (v.violation_type or '').lower()
                if 'critical' in vtype or 'admin' in vtype or 'privilege' in vtype:
                    risk_data['critical_count'] += 1
                elif 'high' in vtype or 'unauthorized' in vtype:
                    risk_data['high_count'] += 1
                else:
                    risk_data['medium_count'] += 1
            
            # Calculate risk percentage
            total_violations = len(violations)
            if total_violations > 0:
                # Weight: critical=3, high=2, medium=1
                weighted_score = (risk_data['critical_count'] * 3 + 
                                  risk_data['high_count'] * 2 + 
                                  risk_data['medium_count'] * 1)
                # Normalize to 0-100 (cap at 100)
                risk_data['risk_percent'] = min(100, int((weighted_score / max(total_violations * 3, 1)) * 100))
                
                if risk_data['risk_percent'] >= 70:
                    risk_data['risk_level'] = 'critical'
                    risk_data['description'] = 'Critical security issues detected. Immediate action recommended.'
                elif risk_data['risk_percent'] >= 40:
                    risk_data['risk_level'] = 'high'
                    risk_data['description'] = 'Significant access control issues found. Review recommended.'
                elif risk_data['risk_percent'] >= 20:
                    risk_data['risk_level'] = 'medium'
                    risk_data['description'] = 'Some access control issues detected. Consider reviewing.'
                else:
                    risk_data['risk_level'] = 'low'
                    risk_data['description'] = 'Low risk detected. Continue monitoring.'
            else:
                risk_data['description'] = 'No violations found in latest scan.'
    
    # ✅ Generate user initials for avatar
    username = user.username
    if len(username) >= 2:
        user_initials = username[:2].upper()
    else:
        user_initials = username.upper()

    # ✅ Render dashboard
    return render_template(
        'dashboard.html',
        username=username,
        user_initials=user_initials,
        scans=scans,
        total_scans=total_scans,
        total_vulns=total_vulns,
        total_urls=total_urls,
        total_roles=total_roles,
        risk_data=risk_data,
        is_admin=user.is_admin
    )

# -------------------------------------------------------
# Quick Scan Page Route
# -------------------------------------------------------
@main.route('/quick-scan')
def quick_scan():
    # Check if logged in
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    user_id = session['user_id']
    user = SystemUser.query.get(user_id)
    
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    
    # Get user's applications for dropdown (optional)
    applications = Application.query.filter_by(user_id=user_id).all()
    
    return render_template(
        'quick_scan.html',
        username=user.username,
        applications=applications,
        is_admin=user.is_admin
    )


# -------------------------------------------------------
# Start Quick Scan API (POST)
# -------------------------------------------------------
@main.route('/api/quick-scan/start', methods=['POST'])
def start_quick_scan():
    """
    Start a quick vulnerability scan for a single target.
    
    Accepts credentials in the existing frontend format and converts
    them to auth_profiles for the scanner.
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        data = request.get_json() or {}

        # Preflight: ensure Playwright is installed
        try:
            import playwright.sync_api  # noqa: F401
        except Exception:
            return jsonify({
                'success': False,
                'message': 'Playwright is not installed. Please install it to enable crawling.'
            }), 500

        # Extract form data (matches quick_scan.html form)
        app_name = data.get('app_name', '').strip()
        raw_target_url = data.get('target_url', '').strip() or data.get('baseURL', '').strip()
        max_depth = int(data.get('max_depth', 3))
        max_pages = int(data.get('max_pages', 100))
        crawl_delay = int(data.get('crawl_delay', 1000))  # Delay in milliseconds
        timeout = int(data.get('timeout', 30))  # Page timeout in seconds
        
        # Role credentials (frontend format)
        admin_creds = data.get('admin_credentials', {})
        user_creds = data.get('user_credentials', {})
        
        # Test options
        options = data.get('options', {})
        check_bac = options.get('check_broken_access', True)
        check_priv_esc = options.get('check_priv_escalation', True)
        check_session = options.get('check_session', True)
        check_forced_browsing = options.get('check_forced_browsing', True)
        check_auth_bypass = options.get('check_auth_bypass', True)
        capture_screenshots = options.get('capture_screenshots', False)

        # Basic validation
        if not app_name or not raw_target_url:
            return jsonify({'success': False, 'message': 'App name and URL are required.'}), 400

        # Validate URL format
        try:
            from urllib.parse import urlparse, urlunparse
            parsed_target = urlparse(raw_target_url)
            if not parsed_target.scheme or not parsed_target.netloc:
                return jsonify({'success': False, 'message': 'Invalid URL format'}), 400

            # Normalize scan root by removing query/fragment so SPA hashes like "#/login"
            # do not break seed route generation and default login URL construction.
            target_path = parsed_target.path or '/'
            scan_base_url = urlunparse(
                (parsed_target.scheme, parsed_target.netloc, target_path, '', '', '')
            ).rstrip('/')
            if not scan_base_url:
                scan_base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"

            def _default_login_url_for_target() -> str:
                fragment = (parsed_target.fragment or '').strip()
                fragment_lower = fragment.lower()
                is_spa_hash = fragment.startswith('/')
                login_hash = any(k in fragment_lower for k in ('login', 'signin', 'sign-in', 'auth'))

                if is_spa_hash and login_hash:
                    return urlunparse(
                        (
                            parsed_target.scheme,
                            parsed_target.netloc,
                            parsed_target.path or '/',
                            '',
                            parsed_target.query,
                            fragment
                        )
                    )

                app_name_lower = (app_name or '').lower()
                url_lower = (raw_target_url or '').lower()
                use_spa_login = 'juice' in app_name_lower or 'juice' in url_lower or is_spa_hash
                return f"{scan_base_url}/#/login" if use_spa_login else f"{scan_base_url}/login"

            default_login_url = _default_login_url_for_target()

        except Exception:
            return jsonify({'success': False, 'message': 'Invalid URL format'}), 400

        # Check or create Application
        # NOTE: We intentionally include `name` in the lookup so that scans against the
        # same base_url can retain the per-run application name instead of all historical
        # scans showing the first created application's name.
        application = Application.query.filter_by(base_url=scan_base_url, name=app_name, user_id=user_id).first()
        if not application:
            application = Application(
                user_id=user_id,
                name=app_name,
                base_url=scan_base_url,
                description=f"Quick scan target: {app_name}",
                created_at=datetime.utcnow()
            )
            db.session.add(application)
            db.session.commit()

        # Create Scan entry
        new_scan = Scan(
            app_id=application.app_id,
            user_id=user_id,
            baseURL=scan_base_url,
            maxDepth=max_depth,
            start_time=datetime.utcnow(),
            status='Queued',
            vulnerable_count=0,
            created_at=datetime.utcnow()
        )
        db.session.add(new_scan)
        db.session.commit()

        # Build auth_profiles list from frontend credentials
        # Convert existing admin/user format to dynamic profiles
        auth_profiles = []
        
        admin_login_url = (admin_creds.get('login_url') or '').strip() or default_login_url
        user_login_url = (user_creds.get('login_url') or '').strip() or default_login_url

        # Admin profile (highest privilege)
        if admin_creds.get('username') and admin_creds.get('password'):
            auth_profiles.append({
                'role_name': 'admin',
                'username': admin_creds['username'],
                'password': admin_creds['password'],
                'login_url': admin_login_url,
                'privilege_level': 2  # Highest privilege
            })
            # Save credential to database
            new_cred = Credential(
                app_id=application.app_id,
                role_name='admin',
                email=admin_creds['username'],
                password=admin_creds['password'],
                created_at=datetime.utcnow()
            )
            db.session.add(new_cred)
        
        # User profile (lower privilege)
        if user_creds.get('username') and user_creds.get('password'):
            auth_profiles.append({
                'role_name': 'user',
                'username': user_creds['username'],
                'password': user_creds['password'],
                'login_url': user_login_url,
                'privilege_level': 1  # Lower privilege
            })
            # Save credential to database
            new_cred = Credential(
                app_id=application.app_id,
                role_name='user',
                email=user_creds['username'],
                password=user_creds['password'],
                created_at=datetime.utcnow()
            )
            db.session.add(new_cred)
        
        # Manual login options (for complex auth flows)
        manual_login = data.get('manual_login', False)
        login_wait_seconds = int(data.get('login_wait_seconds', 120))
        
        db.session.commit()

        dvwa_security_level = (
            (data.get('dvwa_security_level') or '').strip().lower()
            or _infer_dvwa_security_level(app_name)
        )
        if dvwa_security_level not in (None, '', 'low', 'medium', 'high', 'impossible'):
            dvwa_security_level = None

        spa_mode = False
        try:
            app_name_lower = (app_name or '').lower()
            base_url_lower = (raw_target_url or '').lower()
            if 'juice' in app_name_lower or 'juice' in base_url_lower or (parsed_target.fragment or '').startswith('/'):
                spa_mode = True
        except Exception:
            spa_mode = False

        # Build scanner config (new format with auth_profiles)
        scanner_config = {
            'base_url': scan_base_url,
            'max_depth': max_depth,
            'max_pages': max_pages,
            'crawl_delay': crawl_delay,
            'timeout': timeout,
            'auth_profiles': auth_profiles,
            'check_bac': check_bac,
            'check_priv_escalation': check_priv_esc,
            'check_session': check_session,
            'check_forced_browsing': check_forced_browsing,
            'check_auth_bypass': check_auth_bypass,
            'capture_screenshots': capture_screenshots,
            'manual_login': manual_login,
            'login_wait_seconds': login_wait_seconds,
            'dvwa_security_level': dvwa_security_level,
            'spa_mode': spa_mode
        }

        # Import and start scanner in background
        from app.scanner import run_scan_background
        from flask import current_app
        run_scan_background(new_scan.scan_id, scanner_config, db, current_app._get_current_object())

        return jsonify({
            'success': True,
            'message': f'Quick scan started for {scan_base_url}',
            'scan_id': new_scan.scan_id,
            'redirect_url': url_for('main.dashboard')
        }), 201

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        print(f"❌ Quick Scan Error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500


@main.route('/api/quick-scan/<int:scan_id>/results', methods=['GET'])
def get_scan_results(scan_id):
    """Get detailed results for a completed scan."""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404

        # Get URLs and violations
        urls = URL.query.filter_by(scan_id=scan_id).all()
        violations = []
        
        for url in urls:
            url_violations = Violation.query.filter_by(url_id=url.url_id).all()
            for v in url_violations:
                violations.append({
                    'url': url.url,
                    'violation_type': v.violation_type,
                    'role_attempted': v.role_attempted,
                    'expected_access': v.expected_access,
                    'actual_access': v.actual_access,
                    'created_at': v.created_at.isoformat() if v.created_at else None
                })

        return jsonify({
            'success': True,
            'scan': {
                'scan_id': scan.scan_id,
                'base_url': scan.baseURL,
                'status': scan.status,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'urls_found': len(urls),
                'vulnerable_count': scan.vulnerable_count
            },
            'violations': violations
        }), 200

    except Exception as e:
        print(f"❌ Get Results Error: {e}")
        return jsonify({'success': False, 'message': 'Internal Server Error'}), 500

# -------------------------------------------------------
# Get Scan Status API
# -------------------------------------------------------
@main.route('/api/scans/<int:scan_id>/status', methods=['GET'])
def get_scan_status(scan_id):
    """
    Get current status of a scan for the logged-in user.
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()

        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404

        return jsonify({
            'success': True,
            'scan': {
                'scan_id': scan.scan_id,
                'status': scan.status,
                'vulnerable_count': scan.vulnerable_count or 0,
                'start_time': scan.start_time.isoformat() if scan.start_time else None,
                'end_time': scan.end_time.isoformat() if scan.end_time else None,
                'baseURL': scan.baseURL,
                'app_name': scan.application.name if scan.application else 'Unknown'
            }
        })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------
# Get Scan Progress API (Real-time)
# -------------------------------------------------------
@main.route('/api/scans/<int:scan_id>/progress', methods=['GET'])
def get_scan_progress(scan_id):
    """
    Get real-time progress of a running scan.
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        
        # Verify scan belongs to user
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404

        # Get progress from scanner
        from app.scanner import scan_progress
        
        if scan_id in scan_progress:
            progress_data = scan_progress[scan_id].copy()
            progress_data['scan_id'] = scan_id
            return jsonify({'success': True, 'progress': progress_data})
        else:
            # No progress data yet, return basic info
            return jsonify({
                'success': True,
                'progress': {
                    'scan_id': scan_id,
                    'status': scan.status,
                    'current_activity': 'Initializing...',
                    'progress_percent': 0
                }
            })

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Get User's Scans API
# -------------------------------------------------------
@main.route('/api/scans', methods=['GET'])
def get_user_scans():
    """
    Fetch all scans for the authenticated user (limit 50 recent).
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.created_at.desc()).limit(50).all()

        scan_list = [{
            'scan_id': s.scan_id,
            'baseURL': s.baseURL,
            'status': s.status,
            'vulnerable_count': s.vulnerable_count or 0,
            'start_time': s.start_time.isoformat() if s.start_time else None,
            'end_time': s.end_time.isoformat() if s.end_time else None,
            'app_name': s.application.name if s.application else 'Unknown'
        } for s in scans]

        return jsonify({'success': True, 'scans': scan_list})

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Delete Scan API
# -------------------------------------------------------
@main.route('/api/scans/<int:scan_id>', methods=['DELETE'])
def delete_scan(scan_id):
    """
    Delete a specific scan for the authenticated user.
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()

        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404

        # Delete related records first to handle foreign key constraints
        # 1. Delete Report records
        Report.query.filter_by(scan_id=scan.scan_id).delete()
        
        # 2. Get all URLs for this scan and delete their violations
        urls = URL.query.filter_by(scan_id=scan.scan_id).all()
        for url in urls:
            Violation.query.filter_by(url_id=url.url_id).delete()
        
        # 3. Delete URL records
        URL.query.filter_by(scan_id=scan.scan_id).delete()
        
        # 4. Now delete the scan itself
        db.session.delete(scan)
        db.session.commit()

        return jsonify({'success': True, 'message': 'Scan deleted successfully'})

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------
# Batch Scan Page Route
# -------------------------------------------------------

@main.route('/batch-scan')
def batch_scan():
    if "username" not in session:
        return redirect(url_for('main.login'))

    username = session['username']
    user = SystemUser.query.filter_by(username=username).first()
    if not user:
        return redirect(url_for('main.login'))

    # Fetch all applications owned by this user (for dropdown if needed)
    apps = Application.query.filter_by(user_id=user.user_id).all()

    return render_template(
        'batch_scan.html',
        username=username,
        apps=apps,
        is_admin=user.is_admin
    )


# API to start batch scan
@main.route('/api/batch-scans/start', methods=['POST'])
def start_batch_scan():
    """
    Start batch vulnerability scans for multiple target applications.
    
    Role Logic (STRICT):
    - No credentials → Guest only
    - Admin only → Admin + Guest
    - User only → User + Guest
    - Admin + User → Admin + User + Guest
    
    Each target URL is scanned independently with its own scan record.
    """
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        user = SystemUser.query.get(user_id)

        if not user:
            return jsonify({'success': False, 'message': 'User not found'}), 404

        data = request.get_json() or {}

        # Preflight: ensure Playwright is installed
        try:
            import playwright.sync_api  # noqa: F401
        except Exception:
            return jsonify({
                'success': False,
                'message': 'Playwright is not installed. Please install it to enable crawling.'
            }), 500

        # Extract form data
        auth_profiles = data.get('auth_profiles', [])
        options = data.get('options', {})
        max_depth = int(data.get('max_depth', 3))
        max_pages = int(data.get('max_pages', 100))
        delay_between_scans = int(data.get('delay_between_scans', 5))

        # Check BAC-related options
        check_bac = options.get('check_broken_access_control', True)
        check_priv_esc = options.get('check_privilege_escalation', True)
        check_session = options.get('check_session_management', True)
        check_forced_browsing = options.get('check_forced_browsing', True)
        check_auth_bypass = options.get('check_auth_bypass', True)
        capture_screenshots = options.get('capture_screenshots', False)

        if not auth_profiles:
            return jsonify({'success': False, 'message': 'No authentication profiles provided.'}), 400

        # Group auth profiles by target_website
        # Each target URL will have its own set of credentials
        targets = {}
        for profile in auth_profiles:
            target_url = profile.get('target_website', '').strip()
            if not target_url:
                continue
            
            # Validate URL format
            try:
                from urllib.parse import urlparse
                parsed = urlparse(target_url)
                if not parsed.scheme or not parsed.netloc:
                    continue
            except:
                continue
            
            if target_url not in targets:
                targets[target_url] = {
                    'profile_name': profile.get('profile_name', 'Batch Scan Target'),
                    'target_website': target_url,
                    'login_url': profile.get('login_url', f"{target_url}/login"),
                    'credentials': []
                }
            
            # Add credential to this target
            role = profile.get('user_role', 'user').lower()
            username = profile.get('username', '').strip()
            password = profile.get('password', '')
            
            if username and password:
                targets[target_url]['credentials'].append({
                    'role': role,
                    'username': username,
                    'password': password,
                    'login_url': profile.get('login_url', '') or targets[target_url]['login_url']
                })

        if not targets:
            return jsonify({'success': False, 'message': 'No valid target websites found.'}), 400

        scan_ids = []
        
        # Process each target independently
        for target_url, target_data in targets.items():
            # Get or create Application (include `name` so each batch target keeps its label)
            app_name = target_data['profile_name'] or f"Batch Target - {target_url[:50]}"
            application = Application.query.filter_by(base_url=target_url, name=app_name, user_id=user_id).first()
            if not application:
                application = Application(
                    user_id=user_id,
                    name=app_name,
                    base_url=target_url,
                    description=f"Batch scan target: {target_url}",
                    created_at=datetime.utcnow()
                )
                db.session.add(application)
                db.session.commit()

            # Create Scan entry
            new_scan = Scan(
                app_id=application.app_id,
                user_id=user_id,
                baseURL=target_url,
                maxDepth=max_depth,
                start_time=datetime.utcnow(),
                status='Queued',
                vulnerable_count=0,
                created_at=datetime.utcnow()
            )
            db.session.add(new_scan)
            db.session.commit()

            # Build auth_profiles list for scanner (new format)
            # Apply role logic: determine which roles to include
            scanner_profiles = []
            has_admin = False
            has_user = False
            
            for cred in target_data['credentials']:
                role = cred['role'].lower()
                
                if role == 'admin' and cred['username']:
                    has_admin = True
                    scanner_profiles.append({
                        'role_name': 'admin',
                        'username': cred['username'],
                        'password': cred['password'],
                        'login_url': cred['login_url'],
                        'privilege_level': 2  # Highest
                    })
                    # Save credential to database
                    new_cred = Credential(
                        app_id=application.app_id,
                        role_name='admin',
                        email=cred['username'],
                        password=cred['password'],
                        created_at=datetime.utcnow()
                    )
                    db.session.add(new_cred)
                    
                elif cred['username']:  # user or other roles
                    has_user = True
                    scanner_profiles.append({
                        'role_name': role if role else 'user',
                        'username': cred['username'],
                        'password': cred['password'],
                        'login_url': cred['login_url'],
                        'privilege_level': 1  # Lower than admin
                    })
                    # Save credential to database
                    new_cred = Credential(
                        app_id=application.app_id,
                        role_name=role or 'user',
                        email=cred['username'],
                        password=cred['password'],
                        created_at=datetime.utcnow()
                    )
                    db.session.add(new_cred)

            db.session.commit()

            dvwa_security_level = (
                (target_data.get('dvwa_security_level') or '').strip().lower()
                or _infer_dvwa_security_level(app_name)
            )
            if dvwa_security_level not in (None, '', 'low', 'medium', 'high', 'impossible'):
                dvwa_security_level = None

            spa_mode = False
            try:
                app_name_lower = (app_name or '').lower()
                target_url_lower = (target_url or '').lower()
                if 'juice' in app_name_lower or 'juice' in target_url_lower:
                    spa_mode = True
            except Exception:
                spa_mode = False

            # Build scanner config (new format with auth_profiles)
            # The QuickScanner will determine roles to crawl based on auth_profiles
            scanner_config = {
                'base_url': target_url,
                'max_depth': max_depth,
                'max_pages': max_pages,
                'auth_profiles': scanner_profiles,
                'check_bac': check_bac,
                'check_priv_escalation': check_priv_esc,
                'check_session': check_session,
                'check_forced_browsing': check_forced_browsing,
                'check_auth_bypass': check_auth_bypass,
                'capture_screenshots': capture_screenshots,
                'dvwa_security_level': dvwa_security_level,
                'spa_mode': spa_mode
            }

            # Import and start scanner in background
            from app.scanner import run_scan_background
            from flask import current_app
            run_scan_background(new_scan.scan_id, scanner_config, db, current_app._get_current_object())
            
            scan_ids.append(new_scan.scan_id)
            print(f"✅ Batch scan started for: {target_url} (scan_id: {new_scan.scan_id})")

        return jsonify({
            'success': True,
            'message': f'Batch scan started for {len(scan_ids)} target(s).',
            'scan_count': len(scan_ids),
            'scan_ids': scan_ids,
            'redirect_url': url_for('main.dashboard')
        }), 201

    except Exception as e:
        db.session.rollback()
        import traceback
        traceback.print_exc()
        print(f"❌ Batch Scan Error: {e}")
        return jsonify({'success': False, 'message': str(e)}), 500

# -------------------------------------------------------
# Reports Page Route
# -------------------------------------------------------
@main.route('/reports')
def reports():
    """Main reports listing page"""
    # Check if logged in
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    user_id = session['user_id']
    user = SystemUser.query.get(user_id)
    
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    
    # Fetch user's scans for the reports list
    scans = Scan.query.filter_by(user_id=user_id).order_by(Scan.created_at.desc()).all()
    
    return render_template(
        'scan_history.html',
        username=user.username,
        scans=scans,
        is_admin=user.is_admin
    )

# -------------------------------------------------------
# Individual Report Page Route
# -------------------------------------------------------
@main.route('/report')
@main.route('/report/<int:scan_id>')
def report(scan_id=None):
    """Display individual scan report page"""
    try:
        # Check if logged in
        if 'user_id' not in session:
            return redirect(url_for('main.login'))

        user_id = session['user_id']
        user = SystemUser.query.get(user_id)

        if not user:
            session.clear()
            return redirect(url_for('main.login'))

        # If no scan_id provided, redirect to reports list
        if not scan_id:
            return redirect(url_for('main.reports'))

        # Fetch the specific scan
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()

        if not scan:
            # Scan not found or doesn't belong to user
            return redirect(url_for('main.reports'))

        # Fetch URLs for this scan
        urls = URL.query.filter_by(scan_id=scan_id).all()

        # Fetch all violations for this scan in a single query (prevents N+1 queries)
        violations = []
        rows = (
            db.session.query(Violation, URL.url)
            .join(URL, Violation.url_id == URL.url_id)
            .filter(URL.scan_id == scan_id)
            .order_by(Violation.created_at.desc())
            .all()
        )
        for v, url_str in rows:
            violations.append({
                'url': url_str,
                'violation_type': v.violation_type,
                'role_attempted': v.role_attempted,
                'expected_access': v.expected_access,
                'actual_access': v.actual_access,
                'created_at': v.created_at
            })

        # Fetch report data (optional metadata)
        report_data = Report.query.filter_by(scan_id=scan_id).first()

        # Calculate scan duration
        duration = None
        if scan.start_time and scan.end_time:
            delta = scan.end_time - scan.start_time
            duration = str(delta).split('.')[0]  # Remove microseconds

        return render_template(
            'report.html',
            username=user.username,
            scan=scan,
            violations=violations,
            urls=urls,
            urls_count=len(urls),
            duration=duration,
            report_data=report_data,
            is_admin=user.is_admin
        )
    except Exception as e:
        import traceback
        traceback.print_exc()
        # Avoid taking down the whole site on a report rendering error.
        return jsonify({'success': False, 'message': f'Report rendering failed: {str(e)}'}), 500


# -------------------------------------------------------
# Export Single Scan as CSV
# -------------------------------------------------------
@main.route('/api/scans/<int:scan_id>/export', methods=['GET'])
def export_scan_csv(scan_id):
    """Export a single scan report as CSV file"""
    try:
        from flask import make_response
        import io
        import csv

        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
        
        if not scan:
            return jsonify({'success': False, 'message': 'Scan not found'}), 404

        # Create CSV in memory
        output = io.StringIO()
        writer = csv.writer(output)

        # Header section
        writer.writerow(['Scan Report'])
        writer.writerow([])
        writer.writerow(['Scan ID', f'#SC-{scan_id:04d}'])
        writer.writerow(['Application', scan.application.name if scan.application else 'Unknown'])
        writer.writerow(['URL', scan.baseURL or 'N/A'])
        writer.writerow(['Status', scan.status or 'Unknown'])
        writer.writerow(['Start Time', scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else 'N/A'])
        writer.writerow(['End Time', scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else 'N/A'])
        writer.writerow(['Vulnerabilities Found', scan.vulnerable_count or 0])
        writer.writerow([])

        # Get URLs for this scan
        urls = URL.query.filter_by(scan_id=scan_id).all()
        
        # Discovered URLs section
        writer.writerow(['Discovered URLs'])
        writer.writerow(['URL', 'HTTP Status', 'Accessible Roles'])
        for url in urls:
            writer.writerow([
                url.url,
                url.http_status or 'N/A',
                url.accessible_roles or 'N/A'
            ])
        writer.writerow([])

        # Violations section
        writer.writerow(['Violations'])
        writer.writerow(['URL', 'Violation Type', 'Role Attempted', 'Expected Access', 'Actual Access', 'Detected At'])
        
        # Fetch violations in one query to avoid N+1 queries
        v_rows = (
            db.session.query(Violation, URL.url)
            .join(URL, Violation.url_id == URL.url_id)
            .filter(URL.scan_id == scan_id)
            .order_by(Violation.created_at.asc())
            .all()
        )
        for v, url_str in v_rows:
            writer.writerow([
                url_str,
                v.violation_type or 'N/A',
                v.role_attempted or 'N/A',
                v.expected_access or 'N/A',
                v.actual_access or 'N/A',
                v.created_at.strftime('%Y-%m-%d %H:%M:%S') if v.created_at else 'N/A'
            ])

        # Create response
        output.seek(0)
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.csv'
        
        return response

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Bulk Export Scans (ZIP of CSVs)
# -------------------------------------------------------
@main.route('/api/scans/bulk-export', methods=['POST'])
def bulk_export_scans():
    """Export multiple scan reports as a ZIP file containing CSVs"""
    try:
        from flask import send_file
        import io
        import zipfile
        import csv

        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        data = request.get_json()
        scan_ids = data.get('scan_ids', [])

        if not scan_ids:
            return jsonify({'success': False, 'message': 'No scan IDs provided'}), 400

        # Create ZIP file in memory
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            for scan_id in scan_ids:
                scan = Scan.query.filter_by(scan_id=int(scan_id), user_id=user_id).first()
                if not scan:
                    continue

                # Create CSV for this scan
                output = io.StringIO()
                writer = csv.writer(output)

                # Header section
                writer.writerow(['Scan Report'])
                writer.writerow([])
                writer.writerow(['Scan ID', f'#SC-{scan.scan_id:04d}'])
                writer.writerow(['Application', scan.application.name if scan.application else 'Unknown'])
                writer.writerow(['URL', scan.baseURL or 'N/A'])
                writer.writerow(['Status', scan.status or 'Unknown'])
                writer.writerow(['Start Time', scan.start_time.strftime('%Y-%m-%d %H:%M:%S') if scan.start_time else 'N/A'])
                writer.writerow(['End Time', scan.end_time.strftime('%Y-%m-%d %H:%M:%S') if scan.end_time else 'N/A'])
                writer.writerow(['Vulnerabilities Found', scan.vulnerable_count or 0])
                writer.writerow([])

                # Get URLs and violations for this scan
                urls = URL.query.filter_by(scan_id=scan.scan_id).all()
                
                # URLs section
                writer.writerow(['Discovered URLs'])
                writer.writerow(['URL', 'HTTP Status', 'Accessible Roles'])
                for url in urls:
                    writer.writerow([
                        url.url,
                        url.http_status or 'N/A',
                        url.accessible_roles or 'N/A'
                    ])
                writer.writerow([])

                # Violations section
                writer.writerow(['Violations'])
                writer.writerow(['URL', 'Violation Type', 'Role Attempted', 'Expected Access', 'Actual Access', 'Detected At'])
                # Violations in a single query (prevents N+1 queries)
                v_rows = (
                    db.session.query(Violation, URL.url)
                    .join(URL, Violation.url_id == URL.url_id)
                    .filter(URL.scan_id == scan.scan_id)
                    .order_by(Violation.created_at.asc())
                    .all()
                )
                for v, url_str in v_rows:
                    writer.writerow([
                        url_str,
                        v.violation_type or 'N/A',
                        v.role_attempted or 'N/A',
                        v.expected_access or 'N/A',
                        v.actual_access or 'N/A',
                        v.created_at.strftime('%Y-%m-%d %H:%M:%S') if v.created_at else 'N/A'
                    ])

                # Add CSV to ZIP
                zf.writestr(f'scan_report_{scan.scan_id}.csv', output.getvalue())

        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='scan_reports.zip'
        )

    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Bulk Delete Scans
# -------------------------------------------------------
@main.route('/api/scans/bulk-delete', methods=['POST'])
def bulk_delete_scans():
    """Delete multiple scans for the authenticated user"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        data = request.get_json()
        scan_ids = data.get('scan_ids', [])

        if not scan_ids:
            return jsonify({'success': False, 'message': 'No scan IDs provided'}), 400

        # Delete each scan that belongs to the user
        deleted_count = 0
        for scan_id in scan_ids:
            scan = Scan.query.filter_by(scan_id=int(scan_id), user_id=user_id).first()
            if scan:
                # Delete related records first to handle foreign key constraints
                # 1. Delete Report records
                Report.query.filter_by(scan_id=scan.scan_id).delete()
                
                # 2. Get all URLs for this scan and delete their violations
                urls = URL.query.filter_by(scan_id=scan.scan_id).all()
                for url in urls:
                    Violation.query.filter_by(url_id=url.url_id).delete()
                
                # 3. Delete URL records
                URL.query.filter_by(scan_id=scan.scan_id).delete()
                
                # 4. Now delete the scan itself
                db.session.delete(scan)
                deleted_count += 1

        db.session.commit()

        return jsonify({
            'success': True, 
            'message': f'{deleted_count} scan(s) deleted successfully',
            'deleted_count': deleted_count
        })

    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Settings Page Route
# -------------------------------------------------------
@main.route('/settings')
def settings():
    """Settings page for user account and preferences"""
    # Check if logged in
    if 'user_id' not in session:
        return redirect(url_for('main.login'))
    
    user_id = session['user_id']
    user = SystemUser.query.get(user_id)
    
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    
    return render_template(
        'settings.html',
        username=user.username,
        email=user.email,
        full_name=session.get('full_name', ''),
        is_admin=user.is_admin
    )


# -------------------------------------------------------
# Logout Route
# -------------------------------------------------------
@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))
