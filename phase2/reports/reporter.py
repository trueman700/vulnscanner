from typing import List, Dict, Optional, Union
from fpdf import FPDF, FPDFException
from fpdf.enums import XPos, YPos
import matplotlib.pyplot as plt
import numpy as np
import os
import tempfile
import json
import logging
from datetime import datetime
from pathlib import Path
import seaborn as sns

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class PDFReporter:
    """Enhanced PDF report generator for vulnerability scan results"""
    
    def __init__(self):
        """Initialize with modern FPDF settings"""
        self.pdf = FPDF()
        self.pdf.set_auto_page_break(auto=True, margin=15)
        self.pdf.set_margins(left=15, top=15, right=15)
        self.pdf.set_doc_option('core_fonts_encoding', 'utf-8')
        self._configure_styles()
        
    def _configure_styles(self):
        """Define consistent styles for the report"""
        self.styles = {
            'title': {'font': 'Helvetica', 'size': 16, 'style': 'B'},
            'header': {'font': 'Helvetica', 'size': 12, 'style': 'B'},
            'subheader': {'font': 'Helvetica', 'size': 11, 'style': 'B'},
            'body': {'font': 'Helvetica', 'size': 10},
            'critical': {'fill': (255, 204, 204)},  # Red
            'high': {'fill': (255, 229, 204)},     # Orange
            'medium': {'fill': (255, 255, 204)},   # Yellow
            'low': {'fill': (204, 255, 204)},      # Green
            'info': {'fill': (204, 229, 255)}      # Blue
        }
    
    def _apply_style(self, style_name: str):
        """Apply a predefined style"""
        style = self.styles.get(style_name, self.styles['body'])
        self.pdf.set_font(style['font'], style.get('style', ''), style['size'])
        if 'fill' in style:
            self.pdf.set_fill_color(*style['fill'])
    
    def _generate_risk_chart(self, vulns: List[Dict]) -> Optional[str]:
        """Generate professional risk distribution chart"""
        try:
            plt.style.use('seaborn')
            fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))
            
            # Severity distribution pie chart
            severities = [v.get('severity', 'unknown').title() for v in vulns]
            severity_counts = {s: severities.count(s) for s in set(severities)}
            colors = {
                'Critical': '#ff6b6b',
                'High': '#ffa502',
                'Medium': '#feca57',
                'Low': '#1dd1a1',
                'Unknown': '#c8d6e5'
            }
            ax1.pie(
                severity_counts.values(),
                labels=severity_counts.keys(),
                autopct='%1.1f%%',
                colors=[colors.get(k, '#c8d6e5') for k in severity_counts.keys()],
                startangle=90
            )
            ax1.set_title('Vulnerability Severity Distribution')
            
            # Risk score histogram
            scores = [v.get('risk_score', 0) for v in vulns if v.get('risk_score')]
            if scores:
                sns.histplot(
                    scores,
                    bins=10,
                    kde=True,
                    color='#54a0ff',
                    ax=ax2,
                    edgecolor='white'
                )
                ax2.set_xlabel('Risk Score')
                ax2.set_ylabel('Count')
                ax2.set_title('Risk Score Distribution')
                ax2.set_xlim(0, 10)
            
            plt.tight_layout()
            
            tmp_chart = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            plt.savefig(tmp_chart.name, dpi=300, bbox_inches='tight')
            plt.close()
            return tmp_chart.name
            
        except Exception as e:
            logger.error(f"Chart generation failed: {e}", exc_info=True)
            return None
    
    def _generate_timeline_chart(self, vulns: List[Dict]) -> Optional[str]:
        """Generate vulnerability discovery timeline chart"""
        try:
            dates = []
            for vuln in vulns:
                if 'discovered' in vuln:
                    try:
                        dates.append(datetime.strptime(vuln['discovered'], '%Y-%m-%d'))
                    except ValueError:
                        continue
            
            if not dates:
                return None
                
            plt.style.use('seaborn')
            plt.figure(figsize=(8, 4))
            
            date_counts = {}
            for date in dates:
                date_str = date.strftime('%Y-%m-%d')
                date_counts[date_str] = date_counts.get(date_str, 0) + 1
                
            plt.plot(
                list(date_counts.keys()),
                list(date_counts.values()),
                marker='o',
                color='#5f27cd',
                linestyle='-',
                linewidth=2
            )
            plt.title('Vulnerability Discovery Timeline')
            plt.xlabel('Date')
            plt.ylabel('Vulnerabilities Found')
            plt.xticks(rotation=45)
            plt.grid(True, alpha=0.3)
            
            tmp_chart = tempfile.NamedTemporaryFile(suffix='.png', delete=False)
            plt.savefig(tmp_chart.name, dpi=300, bbox_inches='tight')
            plt.close()
            return tmp_chart.name
            
        except Exception as e:
            logger.warning(f"Timeline chart generation failed: {e}")
            return None
    
    def _add_metadata_section(self, metadata: Dict):
        """Add report metadata section"""
        self._apply_style('title')
        self.pdf.cell(0, 10, "VULNERABILITY ASSESSMENT REPORT", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        
        self._apply_style('subheader')
        self.pdf.cell(40, 8, "Scan Target:", new_x=XPos.LMARGIN)
        self._apply_style('body')
        self.pdf.cell(0, 8, metadata.get('scan_target', 'Unknown'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self._apply_style('subheader')
        self.pdf.cell(40, 8, "Scan Date:", new_x=XPos.LMARGIN)
        self._apply_style('body')
        self.pdf.cell(0, 8, metadata.get('generated_at', 'Unknown'), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        if 'scan_duration' in metadata:
            self._apply_style('subheader')
            self.pdf.cell(40, 8, "Duration:", new_x=XPos.LMARGIN)
            self._apply_style('body')
            self.pdf.cell(0, 8, metadata['scan_duration'], new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.pdf.ln(10)
    
    def _add_summary_section(self, vulns: List[Dict]):
        """Add executive summary section with charts"""
        if not vulns:
            return
            
        self._apply_style('header')
        self.pdf.cell(0, 10, "Executive Summary", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        # Generate and add charts
        risk_chart_path = self._generate_risk_chart(vulns)
        timeline_chart_path = self._generate_timeline_chart(vulns)
        
        if risk_chart_path:
            try:
                self.pdf.image(risk_chart_path, w=180)
                self.pdf.ln(5)
                os.unlink(risk_chart_path)
            except (FileNotFoundError, FPDFException) as e:
                logger.warning(f"Failed to add risk chart: {e}")
        
        if timeline_chart_path:
            try:
                self.pdf.image(timeline_chart_path, w=180)
                self.pdf.ln(5)
                os.unlink(timeline_chart_path)
            except (FileNotFoundError, FPDFException) as e:
                logger.warning(f"Failed to add timeline chart: {e}")
        
        # Add summary statistics
        self._apply_style('subheader')
        self.pdf.cell(0, 8, "Key Statistics:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        stats = {
            "Total Vulnerabilities": len(vulns),
            "Critical": sum(1 for v in vulns if v.get('severity', '').lower() == 'critical'),
            "High": sum(1 for v in vulns if v.get('severity', '').lower() == 'high'),
            "Medium": sum(1 for v in vulns if v.get('severity', '').lower() == 'medium'),
            "Low": sum(1 for v in vulns if v.get('severity', '').lower() == 'low'),
            "Avg. Risk Score": np.mean([v.get('risk_score', 0) for v in vulns])
        }
        
        self._apply_style('body')
        for label, value in stats.items():
            self.pdf.cell(60, 8, f"{label}:", new_x=XPos.LMARGIN)
            self.pdf.cell(0, 8, str(round(value, 2) if isinstance(value, float) else value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        self.pdf.ln(10)
    
    def _add_vulnerabilities_section(self, vulns: List[Dict]):
        """Add detailed vulnerabilities section"""
        if not vulns:
            return
            
        self._apply_style('header')
        self.pdf.cell(0, 10, "Vulnerability Details", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        
        # Sort by risk score (descending)
        sorted_vulns = sorted(vulns, key=lambda x: x.get('risk_score', 0), reverse=True)
        
        for i, vuln in enumerate(sorted_vulns[:50]):  # Limit to top 50
            severity = vuln.get('severity', 'info').lower()
            self._apply_style(severity if severity in self.styles else 'info')
            
            # Vulnerability header
            self.pdf.cell(0, 8, 
                f"{i+1}. {vuln.get('id', 'VULN-UNKNOWN')} - {vuln.get('name', 'Unnamed Vulnerability')}",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT, fill=True)
            
            # Details table
            self._apply_style('body')
            details = [
                ("Host", vuln.get('host', 'Unknown')),
                ("Port/Service", f"{vuln.get('port', 'N/A')}/{vuln.get('service', 'Unknown')}"),
                ("Severity", vuln.get('severity', 'Unknown').title()),
                ("Risk Score", f"{vuln.get('risk_score', 0):.1f}/10"),
                ("CVSS", vuln.get('cvss', 'N/A')),
                ("Discovered", vuln.get('discovered', 'Unknown'))
            ]
            
            for label, value in details:
                self.pdf.cell(40, 6, f"{label}:", new_x=XPos.LMARGIN)
                self.pdf.cell(0, 6, str(value), new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Description
            self.pdf.multi_cell(0, 6, 
                f"Description: {vuln.get('description', 'No description available')}",
                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # Recommendation
            self._apply_style('subheader')
            self.pdf.cell(0, 6, "Remediation:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            self._apply_style('body')
            self.pdf.multi_cell(0, 6, 
                vuln.get('recommendation', 'No remediation recommendation available'),
                new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            # References if available
            if vuln.get('references'):
                self._apply_style('subheader')
                self.pdf.cell(0, 6, "References:", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
                self._apply_style('body')
                for ref in vuln['references'][:3]:  # Limit to 3 references
                    self.pdf.multi_cell(0, 6, f"- {ref}", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
            
            self.pdf.ln(3)
    
    def _add_appendix_section(self, report_data: Dict):
        """Add technical appendix if needed"""
        if 'scan_details' not in report_data:
            return
            
        self.pdf.add_page()
        self._apply_style('header')
        self.pdf.cell(0, 10, "Technical Appendix", new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self._apply_style('body')
        
        # Add scan details as formatted JSON
        self.pdf.multi_cell(0, 6, 
            json.dumps(report_data['scan_details'], indent=2),
            new_x=XPos.LMARGIN, new_y=YPos.NEXT)
    
    def generate(self, report_data: Dict, filename: Union[str, Path] = "scan_report.pdf") -> bool:
        """
        Generate comprehensive PDF report from scan data
        
        Args:
            report_data: Dictionary containing scan results
            filename: Output file path
            
        Returns:
            bool: True if generation succeeded, False otherwise
        """
        try:
            # Initialize document
            self.pdf = FPDF()
            self.pdf.set_auto_page_break(auto=True, margin=15)
            self.pdf.set_margins(left=15, top=15, right=15)
            self._configure_styles()
            self.pdf.add_page()
            
            # Add report sections
            self._add_metadata_section(report_data.get('metadata', {}))
            self._add_summary_section(report_data.get('vulnerabilities', []))
            self._add_vulnerabilities_section(report_data.get('vulnerabilities', []))
            
            # Add appendix if there are technical details
            if 'scan_details' in report_data:
                self._add_appendix_section(report_data)
            
            # Add footer
            self.pdf.set_y(-15)
            self._apply_style('body')
            self.pdf.cell(0, 10, f"Page {self.pdf.page_no()}", align='C')
            
            # Save output
            output_path = Path(filename)
            self.pdf.output(output_path)
            logger.info(f"Report generated successfully at {output_path.absolute()}")
            return True
            
        except FPDFException as e:
            logger.error(f"PDF generation error: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during report generation: {e}", exc_info=True)
            return False

def generate_report(report_data: Dict, format: str = 'console', output_file: Optional[str] = None) -> bool:
    """
    Generate vulnerability scan report in specified format
    
    Args:
        report_data: Dictionary containing scan results
        format: Output format ('console', 'json', or 'pdf')
        output_file: Optional path for output file
        
    Returns:
        bool: True if generation succeeded, False otherwise
    """
    if not report_data:
        logger.error("No report data provided")
        return False

    try:
        if format == 'console':
            _print_console_report(report_data)
        elif format == 'json':
            output_path = output_file if output_file else 'scan_report.json'
            with open(output_path, 'w') as f:
                json.dump(report_data, f, indent=2)
            logger.info(f"JSON report saved to {output_path}")
        elif format == 'pdf':
            reporter = PDFReporter()
            output_path = output_file if output_file else 'scan_report.pdf'
            success = reporter.generate(report_data, filename=output_path)
            if not success:
                return False
        else:
            logger.error(f"Unsupported report format: {format}")
            return False

        return True
    except Exception as e:
        logger.error(f"Report generation failed: {e}", exc_info=True)
        return False

def _print_console_report(report_data: Dict):
    """Print formatted report to console"""
    try:
        from rich.console import Console
        from rich.table import Table
        from rich.panel import Panel
        from rich.text import Text
        from rich import box
        
        console = Console()
        
        # Header
        meta = report_data.get('metadata', {})
        console.print(Panel.fit(
            f"[bold]Vulnerability Scan Report[/bold]\n"
            f"Target: [cyan]{meta.get('scan_target', 'Unknown')}[/cyan]\n"
            f"Generated: [cyan]{meta.get('generated_at', 'Unknown')}[/cyan]",
            title="Report Summary",
            border_style="blue"
        ))
        
        # Vulnerability summary
        vulns = report_data.get('vulnerabilities', [])
        if vulns:
            severity_counts = {
                'Critical': 0,
                'High': 0,
                'Medium': 0,
                'Low': 0,
                'Unknown': 0
            }
            
            for vuln in vulns:
                severity = vuln.get('severity', 'Unknown').title()
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            console.print(Panel.fit(
                f"[bold]Total Vulnerabilities:[/bold] {len(vulns)}\n"
                f"[red]Critical:[/red] {severity_counts['Critical']}  "
                f"[orange3]High:[/orange3] {severity_counts['High']}  "
                f"[yellow]Medium:[/yellow] {severity_counts['Medium']}  "
                f"[green]Low:[/green] {severity_counts['Low']}  "
                f"[grey]Unknown:[/grey] {severity_counts['Unknown']}",
                title="Vulnerability Summary",
                border_style="blue"
            ))
            
            # Top vulnerabilities table
            table = Table(title="Top Vulnerabilities", box=box.ROUNDED)
            table.add_column("#", style="cyan")
            table.add_column("ID", style="magenta")
            table.add_column("Host:Port")
            table.add_column("Severity")
            table.add_column("Risk Score")
            
            for i, vuln in enumerate(sorted(
                vulns, 
                key=lambda x: x.get('risk_score', 0), 
                reverse=True)[:10]):
                
                severity = vuln.get('severity', 'Unknown').title()
                severity_color = {
                    'Critical': 'red',
                    'High': 'orange3',
                    'Medium': 'yellow',
                    'Low': 'green',
                    'Unknown': 'grey'
                }.get(severity, 'grey')
                
                table.add_row(
                    str(i+1),
                    vuln.get('id', 'VULN-UNKNOWN'),
                    f"{vuln.get('host', '?')}:{vuln.get('port', '?')}",
                    Text(severity, style=severity_color),
                    f"{vuln.get('risk_score', 0):.1f}"
                )
            
            console.print(table)
        else:
            console.print("[green]No vulnerabilities found[/green]")
            
    except ImportError:
        # Fallback to basic console output if rich is not available
        print("\n=== Vulnerability Scan Report ===")
        print(f"\nTarget: {meta.get('scan_target', 'Unknown')}")
        print(f"Generated: {meta.get('generated_at', 'Unknown')}")
        
        if vulns:
            print(f"\nVulnerabilities Found: {len(vulns)}")
            for i, vuln in enumerate(vulns[:10]):
                print(f"\n{i+1}. {vuln.get('id', 'VULN-UNKNOWN')}")
                print(f"Host: {vuln.get('host', 'Unknown')}:{vuln.get('port', 'N/A')}")
                print(f"Severity: {vuln.get('severity', 'Unknown')}")
                print(f"Risk Score: {vuln.get('risk_score', 0):.1f}")
                print(f"Description: {vuln.get('description', 'No description')}")
        else:
            print("\nNo vulnerabilities found")