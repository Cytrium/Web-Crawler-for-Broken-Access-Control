# Copy this code and replace everything from line 483 to the end of app/routes.py

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
    
    return render_template('scan_history.html', username=user.username, scans=scans)

# -------------------------------------------------------
# Individual Report Page Route
# -------------------------------------------------------
@main.route('/report')
@main.route('/report/<int:scan_id>')
def report(scan_id=None):
    """Display individual scan report page"""
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
    
    # Fetch report data (you can expand this based on your Report model)
    report_data = Report.query.filter_by(scan_id=scan_id).first()
    
    return render_template(
        'report.html', 
        username=user.username,
        scan=scan,
        report_data=report_data,
        scan_id=scan_id
    )

# -------------------------------------------------------
# Bulk Delete Scans
# -------------------------------------------------------
@main.route('/api/scans/bulk-delete', methods=['POST'])
def bulk_delete_scans():
    """Delete multiple scans at once"""
    try:
        if 'user_id' not in session:
            return jsonify({'success': False, 'message': 'User not authenticated'}), 401

        user_id = session['user_id']
        data = request.get_json()
        scan_ids = data.get('scan_ids', [])

        if not scan_ids:
            return jsonify({'success': False, 'message': 'No scan IDs provided'}), 400

        # Verify all scans belong to the user and delete them
        deleted_count = 0
        for scan_id in scan_ids:
            scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
            if scan:
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
# Export Single Scan Report (CSV)
# -------------------------------------------------------
@main.route('/api/scans/<int:scan_id>/export', methods=['GET'])
def export_scan(scan_id):
    """Export a single scan report as CSV"""
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

        # Write headers
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

        # Get violations if they exist
        violations = Violation.query.filter_by(scan_id=scan_id).all()
        if violations:
            writer.writerow(['Vulnerabilities'])
            writer.writerow(['URL', 'Type', 'Severity', 'Description'])
            for v in violations:
                writer.writerow([
                    v.url or 'N/A',
                    v.violation_type or 'N/A',
                    v.severity or 'N/A',
                    v.description or 'N/A'
                ])

        # Create response
        response = make_response(output.getvalue())
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename=scan_report_{scan_id}.csv'

        return response

    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500


# -------------------------------------------------------
# Bulk Export Scans (ZIP)
# -------------------------------------------------------
@main.route('/api/scans/bulk-export', methods=['POST'])
def bulk_export_scans():
    """Export multiple scan reports as a ZIP file"""
    try:
        from flask import make_response, send_file
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
                scan = Scan.query.filter_by(scan_id=scan_id, user_id=user_id).first()
                if not scan:
                    continue

                # Create CSV for this scan
                output = io.StringIO()
                writer = csv.writer(output)

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

                violations = Violation.query.filter_by(scan_id=scan_id).all()
                if violations:
                    writer.writerow(['Vulnerabilities'])
                    writer.writerow(['URL', 'Type', 'Severity', 'Description'])
                    for v in violations:
                        writer.writerow([
                            v.url or 'N/A',
                            v.violation_type or 'N/A',
                            v.severity or 'N/A',
                            v.description or 'N/A'
                        ])

                # Add to ZIP
                zf.writestr(f'scan_report_{scan_id}.csv', output.getvalue())

        memory_file.seek(0)

        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='scan_reports.zip'
        )

    except Exception as e:
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
    
    user_id = session['user_id']\
    
    user = SystemUser.query.get(user_id)
    
    if not user:
        session.clear()
        return redirect(url_for('main.login'))
    
    return render_template('settings.html', username=user.username)


# -------------------------------------------------------
# Logout Route
# -------------------------------------------------------
@main.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('main.login'))
