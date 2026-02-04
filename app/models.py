from werkzeug.security import generate_password_hash, check_password_hash
from app import db
from datetime import datetime

# ==============================
# SYSTEM USER TABLE
# ==============================
class SystemUser(db.Model):
    __tablename__ = 'systemuser'

    user_id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=True)  # Nullable for OAuth users
    role = db.Column(db.String(50), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    oauth_provider = db.Column(db.String(20), nullable=True)  # 'google' or 'github'
    oauth_id = db.Column(db.String(100), nullable=True)  # Provider's user ID
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    applications = db.relationship('Application', backref='user', lazy=True)

    # Password handling
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# ==============================
# APPLICATION TABLE
# ==============================
class Application(db.Model):
    __tablename__ = 'application'

    app_id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('systemuser.user_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    base_url = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    scans = db.relationship('Scan', back_populates='application', lazy=True)
    credentials = db.relationship('Credential', backref='application', lazy=True)


# ==============================
# CREDENTIAL TABLE
# ==============================
class Credential(db.Model):
    __tablename__ = 'credential'

    credential_id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey('application.app_id'), nullable=False)
    role_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    password = db.Column(db.String(150), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==============================
# SCAN TABLE
# ==============================
class Scan(db.Model):
    __tablename__ = 'scan'

    scan_id = db.Column(db.Integer, primary_key=True)
    app_id = db.Column(db.Integer, db.ForeignKey('application.app_id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('systemuser.user_id'), nullable=False)

    baseURL = db.Column(db.String(255), nullable=False)
    maxDepth = db.Column(db.Integer, default=3)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime)
    status = db.Column(db.String(50))
    vulnerable_count = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)  # Add this line

    # Relationships
    user = db.relationship('SystemUser', backref=db.backref('scans', lazy=True))
    application = db.relationship('Application', backref=db.backref('scan_list', lazy=True))


# ==============================
# URL TABLE
# ==============================
class URL(db.Model):
    __tablename__ = 'url'

    url_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.scan_id'), nullable=False)
    url = db.Column(db.String(500), nullable=False)
    http_status = db.Column(db.String(10))
    admin_status = db.Column(db.String(10))
    user_status = db.Column(db.String(10))
    guest_status = db.Column(db.String(10))
    accessible_roles = db.Column(db.String(255))

    # Relationships
    violations = db.relationship('Violation', backref='url', lazy=True)


# ==============================
# VIOLATION TABLE
# ==============================
class Violation(db.Model):
    __tablename__ = 'violation'

    violation_id = db.Column(db.Integer, primary_key=True)
    url_id = db.Column(db.Integer, db.ForeignKey('url.url_id'), nullable=False)
    role_attempted = db.Column(db.String(50))
    expected_access = db.Column(db.String(50))
    actual_access = db.Column(db.String(50))
    violation_type = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


# ==============================
# REPORT TABLE
# ==============================
class Report(db.Model):
    __tablename__ = 'report'

    report_id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scan.scan_id'), nullable=False)
    generated_at = db.Column(db.DateTime, default=datetime.utcnow)
    summary = db.Column(db.Text)
