from flask import Flask, render_template, request, send_file, session, jsonify
from flask_socketio import SocketIO, emit, join_room
from scanner import AdvancedVulnerabilityScanner, ScanType
import os
import logging
import json
from datetime import datetime
from threading import Thread
from functools import partial
import traceback

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('webapp.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)  # Required for session management
socketio = SocketIO(app, cors_allowed_origins="*", async_mode='threading')

# Global storage
scanners = {}
results_storage = {}

def get_progress_callback(client_id):
    def callback(percentage, message):
        logger.info(f"Progress for {client_id }: {percentage}% - {message}")
        socketio.emit('progress', {'percentage': percentage, 'message': message}, room=client_id)
    return callback

@app.route('/', methods=['GET', 'POST'])
def index():
    error = None
    result = None
    pdf_generated = False
    new_scan_arguments_field = session.get('scan_arguments', '')
    report_format = session.get('report_format', 'console')

    # Generate a unique client ID if not exists
    if 'client_id' not in session:
        session['client_id'] = f"client_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(8).hex()}"
        logger.info(f"New client session: {session['client_id']}")

    client_id = session['client_id']

    if request.method == 'POST':
        target = request.form.get('target')
        scan_type = request.form.get('scan_type', 'hybrid')
        report_format = request.form.get('report_format', 'console')
        scan_arguments = request.form.get('scan_arguments', '')

        session['report_format'] = report_format
        session['scan_arguments'] = scan_arguments

        logger.info(f"Initiating scan for client {client_id}: target={target}, type={scan_type}, format={report_format}")

        try:
            scanner = AdvancedVulnerabilityScanner()
            scanners[client_id] = scanner
            scan_type_enum = ScanType[scan_type.upper()]

            progress_callback = get_progress_callback(client_id)

            def run_scan_task():
                try:
                    scan_results = scanner.run_scan(target, scan_type_enum, progress_callback)
                    results_storage[client_id] = scan_results
                    report_filename = f'scan_report_{scanner.session_id}.{report_format}'
                    scanner.generate_report(scan_results, report_format, filename=report_filename)
                    socketio.emit('complete', room=client_id)
                except Exception as e:
                    logger.error(f"Scan error for {client_id}: {str(e)}\n{traceback.format_exc()}")
                    results_storage[client_id] = {'error': str(e)}
                    socketio.emit('complete', room=client_id)

            Thread(target=run_scan_task).start()

            return render_template(
                "index.html",
                result=None,
                error=None,
                report_format=report_format,
                pdf_generated=False,
                new_scan_arguments_field=scan_arguments
            )

        except KeyError:
            error = f"Invalid scan type: {scan_type}"
            logger.error(error)
        except ValueError as ve:
            error = f"Validation error: {str(ve)}"
            logger.error(error)
        except Exception as e:
            error = f"Failed to start scan: {str(e)}"
            logger.error(error, exc_info=True)

    # For GET or after complete
    if client_id in results_storage:
        result = results_storage[client_id]
        if not result.get('error'):
            scanner = scanners.get(client_id)
            if scanner:
                report_filename = f'scan_report_{scanner.session_id}.pdf'
                pdf_generated = report_format == 'pdf' and os.path.exists(report_filename)

    return render_template(
        "index.html",
        result=result,
        error=error,
        report_format=report_format,
        pdf_generated=pdf_generated,
        new_scan_arguments_field=new_scan_arguments_field
    )

@app.route('/download_pdf')
def download_pdf():
    try:
        client_id = session.get('client_id')
        if not client_id:
            logger.error("No client ID for PDF download")
            return "Session expired", 400

        scanner = scanners.get(client_id)
        if scanner:
            pdf_path = f"scan_report_{scanner.session_id}.pdf"
        else:
            pdf_files = [f for f in os.listdir('.') if f.startswith('scan_report_') and f.endswith('.pdf')]
            if pdf_files:
                pdf_files.sort(key=lambda x: os.path.getmtime(x), reverse=True)
                pdf_path = pdf_files[0]
            else:
                logger.error("No PDF file found")
                return "PDF report not found", 404

        if os.path.exists(pdf_path):
            return send_file(pdf_path, as_attachment=True)
        else:
            logger.error(f"PDF not found: {pdf_path}")
            return "PDF report not found", 404
    except Exception as e:
        logger.error(f"PDF download error: {str(e)}")
        return "Error downloading PDF", 500

@socketio.on('connect')
def handle_connect():
    if 'client_id' in session:
        join_room(session['client_id'])
        logger.info(f"Client {session['client_id']} connected")
        emit('connected', {'message': 'Connected to scanner'})

@socketio.on('disconnect')
def handle_disconnect():
    if 'client_id' in session:
        logger.info(f"Client {session['client_id']} disconnected")

@socketio.on('cancel_scan')
def handle_cancel_scan():
    client_id = session.get('client_id')
    if client_id:
        logger.info(f"Cancel request for {client_id}")
        scanner = scanners.get(client_id)
        if scanner:
            scanner.cancelled = True
        emit('cancelled', room=client_id)

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)