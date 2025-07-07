from flask import render_template, redirect, url_for, flash, request, jsonify
from flask_login import login_required, current_user
from app import db
from app.scans import bp
from app.models import Scan, ScanResult
from app.scans.forms import NewScanForm
from app.utils.scanner import VulnerabilityScanner
from datetime import datetime
import json

@bp.route('/dashboard')
@login_required
def dashboard():
    scans = current_user.scans.order_by(Scan.timestamp.desc()).limit(5).all()
    return render_template('scans/dashboard.html', title='Dashboard', scans=scans)

@bp.route('/new_scan', methods=['GET', 'POST'])
@login_required
def new_scan():
    form = NewScanForm()
    if form.validate_on_submit():
        scan = Scan(
            target=form.target.data,
            scan_type=form.scan_type.data,
            status='queued',
            author=current_user
        )
        db.session.add(scan)
        db.session.commit()
        
        # Start scan in background
        from app.tasks import launch_scan
        launch_scan.delay(scan.id)
        
        flash('Your scan has been queued!')
        return redirect(url_for('scans.dashboard'))
    return render_template('scans/new_scan.html', title='New Scan', form=form)

@bp.route('/scan/<int:scan_id>')
@login_required
def scan_details(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.author != current_user:
        abort(403)
    return render_template('scans/scan_details.html', title='Scan Details', scan=scan)

@bp.route('/scan_results/<int:scan_id>')
@login_required
def scan_results(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.author != current_user:
        abort(403)
    
    results = {}
    for result in scan.results:
        results[result.result_type] = json.loads(result.raw_data)
    
    return render_template('scans/scan_results.html', 
                         title='Scan Results', 
                         scan=scan, 
                         results=results)

@bp.route('/scan_status/<int:scan_id>')
@login_required
def scan_status(scan_id):
    scan = Scan.query.get_or_404(scan_id)
    if scan.author != current_user:
        abort(403)
    return jsonify({
        'status': scan.status,
        'progress': scan.progress if hasattr(scan, 'progress') else 0
    })