import os
from jinja2 import Environment, FileSystemLoader
import pdfkit

class ReportGenerator:
    def __init__(self, template_dir="templates"):
        self.template_dir = template_dir
        os.makedirs(self.template_dir, exist_ok=True)
        self.template_path = os.path.join(self.template_dir, "report_template.html")
        if not os.path.exists(self.template_path):
            with open(self.template_path, "w") as f:
                f.write("""<!DOCTYPE html>
<html>
<head>
    <title>Vulnerability Report</title>
    <style>
        body { font-family: Arial, sans-serif; }
        table { border-collapse: collapse; width: 100%; }
        th, td { border: 1px solid #ddd; padding: 8px; }
        th { background-color: #f2f2f2; }
    </style>
</head>
<body>
    <h1>Vulnerability Report</h1>
    <p>Target: {{ metadata.scan_target }}</p>
    <p>Generated: {{ metadata.generated_at }}</p>
    <h2>Top Vulnerabilities</h2>
    <table>
        <tr>
            <th>#</th>
            <th>Host</th>
            <th>Port</th>
            <th>Service</th>
            <th>CVE</th>
            <th>CVSS</th>
            <th>Risk Score</th>
            <th>Recommendation</th>
        </tr>
        {% for vuln in vulnerabilities[:10] %}
        <tr>
            <td>{{ loop.index }}</td>
            <td>{{ vuln.get('host', 'unknown') }}</td>
            <td>{{ vuln.get('port', 'N/A') }}</td>
            <td>{{ vuln.get('service', 'N/A') }}</td>
            <td>{{ vuln.get('id', 'CVE-UNKNOWN') }}</td>
            <td>{{ vuln.get('score', 0) }}</td>
            <td>{{ vuln.get('risk_score', 0) }}</td>
            <td>{{ vuln.get('recommendation', 'Not specified') }}</td>
        </tr>
        {% endfor %}
    </table>
</body>
</html>
""")

    def generate(self, report_data: dict, filename: str = "scan_report.pdf"):
        try:
            env = Environment(loader=FileSystemLoader(self.template_dir))
            template = env.get_template("report_template.html")
            html = template.render(**report_data)
            pdfkit.from_string(html, filename)
            return True
        except Exception as e:
            print(f"HTML/PDF report generation failed: {e}")
            return False