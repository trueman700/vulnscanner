from flask import Flask, render_template, request, send_file
import os
from scanner import AdvancedVulnerabilityScanner, ScanType

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    error = None
    pdf_generated = False
    report_format = "console"
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        scan_type = request.form.get("scan_type", "hybrid")
        report_format = request.form.get("report_format", "console")
        if not target:
            error = "Target is required."
        else:
            try:
                scanner = AdvancedVulnerabilityScanner()
                scan_results = scanner.run_scan(target, ScanType[scan_type.upper()])
                result = scan_results
                # Always generate PDF
                scanner.generate_report(scan_results, "pdf")
                pdf_generated = True
                # Optionally, also generate the selected format
                if report_format != "pdf":
                    scanner.generate_report(scan_results, report_format)
            except Exception as e:
                error = f"Scan failed: {e}"
    return render_template(
        "index.html",
        result=result,
        error=error,
        report_format=report_format,
        pdf_generated=pdf_generated
    )

@app.route("/download-pdf")
def download_pdf():
    # Adjust the filename/path as needed
    pdf_path = "scan_report.pdf"
    if not os.path.exists(pdf_path):
        return "PDF report not found. Please run a scan with PDF format first.", 404
    return send_file(pdf_path, as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)