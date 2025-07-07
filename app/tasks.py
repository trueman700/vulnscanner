from celery import Celery
from app import create_app
from app.models import Scan, ScanResult, db
from app.utils.scanner import VulnerabilityScanner
import json

def make_celery(app):
    celery = Celery(
        app.import_name,
        backend=app.config['CELERY_RESULT_BACKEND'],
        broker=app.config['CELERY_BROKER_URL']
    )
    celery.conf.update(app.config)
    return celery

flask_app = create_app()
celery = make_celery(flask_app)

@celery.task(bind=True)
def launch_scan(self, scan_id):
    with flask_app.app_context():
        scan = Scan.query.get(scan_id)
        if not scan:
            return
        
        scan.status = 'running'
        db.session.commit()
        
        scanner = VulnerabilityScanner()
        
        try:
            # Update task id for progress tracking
            self.update_state(state='PROGRESS', meta={'current': 0, 'total': 100})
            
            # Run the scan
            results = scanner.run_scan(scan.target, scan.scan_type)
            
            # Save results
            if results.get('nmap'):
                nmap_result = ScanResult(
                    scan=scan,
                    result_type='nmap',
                    raw_data=json.dumps(results['nmap']),
                    critical_count=len(results['nmap'].get('critical', [])),
                    high_count=len(results['nmap'].get('high', [])),
                    medium_count=len(results['nmap'].get('medium', [])),
                    low_count=len(results['nmap'].get('low', [])),
                    info_count=len(results['nmap'].get('info', []))
                )
                db.session.add(nmap_result)
            
            if results.get('openvas'):
                openvas_result = ScanResult(
                    scan=scan,
                    result_type='openvas',
                    raw_data=json.dumps(results['openvas']),
                    critical_count=len(results['openvas'].get('critical', [])),
                    high_count=len(results['openvas'].get('high', [])),
                    medium_count=len(results['openvas'].get('medium', [])),
                    low_count=len(results['openvas'].get('low', [])),
                    info_count=len(results['openvas'].get('info', []))
                )
                db.session.add(openvas_result)
            
            scan.status = 'completed'
            db.session.commit()
            
        except Exception as e:
            scan.status = 'failed'
            db.session.commit()
            raise