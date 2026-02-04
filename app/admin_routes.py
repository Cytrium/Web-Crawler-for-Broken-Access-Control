# app/admin_routes.py

from flask import Blueprint, render_template, request, redirect, url_for, session, jsonify, flash
from werkzeug.security import check_password_hash
from functools import wraps
from app import db
from app.models import SystemUser, Scan, Application, URL, Violation, Credential

# Initialize the admin blueprint
admin = Blueprint('admin', __name__, url_prefix='/admin')


# -------------------------------------------------------
# Admin Required Decorator (Uses separate admin session)
# -------------------------------------------------------
def admin_required(f):
    """Decorator to require admin authentication via separate admin session."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check for admin-specific session (separate from user session)
        if 'admin_authenticated' not in session or not session.get('admin_authenticated'):
            flash('Please login to the admin panel.', 'error')
            return redirect(url_for('admin.login'))
        
        # Verify admin user still exists and is still an admin
        admin_user_id = session.get('admin_user_id')
        if not admin_user_id:
            session.pop('admin_authenticated', None)
            flash('Admin session invalid. Please login again.', 'error')
            return redirect(url_for('admin.login'))
        
        user = SystemUser.query.get(admin_user_id)
        if not user or not user.is_admin:
            # Clear admin session if user no longer exists or is not admin
            session.pop('admin_authenticated', None)
            session.pop('admin_user_id', None)
            flash('You do not have permission to access the admin panel.', 'error')
            return redirect(url_for('admin.login'))
        
        return f(*args, **kwargs)
    return decorated_function


# -------------------------------------------------------
# Admin Login Page
# -------------------------------------------------------
@admin.route('/login', methods=['GET', 'POST'])
def login():
    """Separate admin login page."""
    # If already authenticated as admin, redirect to dashboard
    if session.get('admin_authenticated') and session.get('admin_user_id'):
        return redirect(url_for('admin.dashboard'))
    
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        
        if not email or not password:
            flash('Please enter both email and password.', 'error')
            return render_template('admin/login.html')
        
        # Find user by email
        user = SystemUser.query.filter_by(email=email).first()
        
        if not user:
            flash('Invalid credentials.', 'error')
            return render_template('admin/login.html')
        
        # Check password
        if not user.check_password(password):
            flash('Invalid credentials.', 'error')
            return render_template('admin/login.html')
        
        # Check if user is an admin
        if not user.is_admin:
            flash('You do not have admin privileges. Please use the regular login.', 'error')
            return render_template('admin/login.html')
        
        # Set admin-specific session (separate from regular user session)
        session['admin_authenticated'] = True
        session['admin_user_id'] = user.user_id
        session['admin_username'] = user.username
        
        flash(f'Welcome, Admin {user.username}!', 'success')
        return redirect(url_for('admin.dashboard'))
    
    return render_template('admin/login.html')


# -------------------------------------------------------
# Admin Logout
# -------------------------------------------------------
@admin.route('/logout')
def logout():
    """Logout from admin panel only (preserves regular user session)."""
    session.pop('admin_authenticated', None)
    session.pop('admin_user_id', None)
    session.pop('admin_username', None)
    flash('You have been logged out of the admin panel.', 'success')
    return redirect(url_for('admin.login'))


# -------------------------------------------------------
# Admin Dashboard
# -------------------------------------------------------
@admin.route('/')
@admin_required
def dashboard():
    """Admin dashboard with overview statistics."""
    stats = {
        'total_users': SystemUser.query.count(),
        'total_scans': Scan.query.count(),
        'total_applications': Application.query.count(),
        'total_violations': Violation.query.count(),
        'total_urls': URL.query.count(),
        'admin_users': SystemUser.query.filter_by(is_admin=True).count(),
    }
    
    # Recent users
    recent_users = SystemUser.query.order_by(SystemUser.created_at.desc()).limit(5).all()
    
    # Recent scans
    recent_scans = Scan.query.order_by(Scan.created_at.desc()).limit(5).all()
    
    return render_template('admin/dashboard.html', stats=stats, recent_users=recent_users, recent_scans=recent_scans)


# -------------------------------------------------------
# User Management
# -------------------------------------------------------
@admin.route('/users')
@admin_required
def users():
    """List all users with search and filter."""
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = SystemUser.query
    
    if search:
        query = query.filter(
            (SystemUser.username.ilike(f'%{search}%')) |
            (SystemUser.email.ilike(f'%{search}%'))
        )
    
    users = query.order_by(SystemUser.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/users.html', users=users, search=search)


@admin.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def edit_user(user_id):
    """Edit user details."""
    user = SystemUser.query.get_or_404(user_id)
    
    if request.method == 'POST':
        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        user.role = request.form.get('role', user.role)
        
        try:
            db.session.commit()
            flash('User updated successfully.', 'success')
            return redirect(url_for('admin.users'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'error')
    
    return render_template('admin/edit_user.html', user=user)


@admin.route('/users/<int:user_id>/delete', methods=['POST'])
@admin_required
def delete_user(user_id):
    """Delete a user."""
    user = SystemUser.query.get_or_404(user_id)
    
    # Prevent self-deletion
    if user.user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': 'You cannot delete your own account.'}), 400
    
    try:
        # Delete related data
        for app in user.applications:
            for cred in app.credentials:
                db.session.delete(cred)
            for scan in app.scans:
                for url in URL.query.filter_by(scan_id=scan.scan_id).all():
                    Violation.query.filter_by(url_id=url.url_id).delete()
                    db.session.delete(url)
                db.session.delete(scan)
            db.session.delete(app)
        
        db.session.delete(user)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'User deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


@admin.route('/users/<int:user_id>/toggle-admin', methods=['POST'])
@admin_required
def toggle_admin(user_id):
    """Toggle admin status for a user."""
    user = SystemUser.query.get_or_404(user_id)
    
    # Prevent removing own admin status
    if user.user_id == session.get('user_id'):
        return jsonify({'success': False, 'message': 'You cannot modify your own admin status.'}), 400
    
    try:
        user.is_admin = not user.is_admin
        db.session.commit()
        status = 'admin' if user.is_admin else 'regular user'
        return jsonify({'success': True, 'message': f'User is now a {status}.', 'is_admin': user.is_admin})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Scan Management
# -------------------------------------------------------
@admin.route('/scans')
@admin_required
def scans():
    """List all scans across all users."""
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = Scan.query.join(SystemUser)
    
    if search:
        query = query.filter(
            (Scan.baseURL.ilike(f'%{search}%')) |
            (SystemUser.username.ilike(f'%{search}%'))
        )
    
    if status_filter:
        query = query.filter(Scan.status == status_filter)
    
    scans = query.order_by(Scan.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/scans.html', scans=scans, search=search, status_filter=status_filter)


@admin.route('/scans/<int:scan_id>/delete', methods=['POST'])
@admin_required
def delete_scan(scan_id):
    """Delete a scan."""
    scan = Scan.query.get_or_404(scan_id)
    
    try:
        # Delete related URLs and violations
        for url in URL.query.filter_by(scan_id=scan.scan_id).all():
            Violation.query.filter_by(url_id=url.url_id).delete()
            db.session.delete(url)
        
        db.session.delete(scan)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Scan deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Application Management
# -------------------------------------------------------
@admin.route('/applications')
@admin_required
def applications():
    """List all applications."""
    search = request.args.get('search', '')
    page = request.args.get('page', 1, type=int)
    per_page = 10
    
    query = Application.query.join(SystemUser)
    
    if search:
        query = query.filter(
            (Application.name.ilike(f'%{search}%')) |
            (Application.base_url.ilike(f'%{search}%')) |
            (SystemUser.username.ilike(f'%{search}%'))
        )
    
    applications = query.order_by(Application.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    return render_template('admin/applications.html', applications=applications, search=search)


@admin.route('/applications/<int:app_id>/delete', methods=['POST'])
@admin_required
def delete_application(app_id):
    """Delete an application."""
    app = Application.query.get_or_404(app_id)
    
    try:
        # Delete related credentials
        for cred in app.credentials:
            db.session.delete(cred)
        
        # Delete related scans
        for scan in app.scans:
            for url in URL.query.filter_by(scan_id=scan.scan_id).all():
                Violation.query.filter_by(url_id=url.url_id).delete()
                db.session.delete(url)
            db.session.delete(scan)
        
        db.session.delete(app)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Application deleted successfully.'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500
