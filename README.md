# VulnScanner

A powerful and efficient vulnerability scanner that performs parallel network scanning and CVE detection using the National Vulnerability Database (NVD) API.

## 🔍 Overview

VulnScanner is an automated security tool designed to identify potential vulnerabilities in network systems. It combines fast parallel network scanning with comprehensive CVE (Common Vulnerabilities and Exposures) detection to provide detailed security assessments of target systems.

## ✨ Features

- **Parallel Network Scanning**: High-performance scanning with concurrent connections for faster results
- **CVE Detection**: Automated vulnerability identification using the NVD (National Vulnerability Database) API
- **JSON Output**: Structured output format for easy integration with other security tools and workflows
- **Automated Setup**: Simple installation process with included setup script
- **Configurable**: Environment-based configuration for API keys and settings

## 📋 Prerequisites

- Python 3.7 or higher
- pip (Python package installer)
- Virtual environment support
- Internet connection (for NVD API access)
- API keys for NVD database

## 🚀 Installation

### 1. Clone the Repository

```bash
git clone https://github.com/trueman700/vulnscanner.git
cd vulnscanner
```

### 2. Run the Setup Script

The setup script will create a virtual environment and install all required dependencies:

```bash
chmod +x setup.sh
./setup.sh
```

### 3. Configure Environment Variables

Copy the example environment file and add your API keys:

```bash
cp .env.example .env
```

Edit the `.env` file and fill in your configuration:

```
NVD_API_KEY=your_nvd_api_key_here
# Add other configuration options as needed
```

## 💻 Usage

### Basic Usage

Activate the virtual environment and run the scanner:

```bash
source venv/bin/activate
python scanner.py
```

### Command Line Options

```bash
# Scan a specific target
python scanner.py --target 192.168.1.1

# Scan a range of IPs
python scanner.py --range 192.168.1.0/24

# Specify output file
python scanner.py --target 192.168.1.1 --output results.json

# Enable verbose mode
python scanner.py --target 192.168.1.1 --verbose

# Specify port range
python scanner.py --target 192.168.1.1 --ports 1-1000
```

### Output Format

The scanner generates JSON output with the following structure:

```json
{
  "scan_date": "2025-11-05T12:00:00Z",
  "target": "192.168.1.1",
  "open_ports": [22, 80, 443],
  "vulnerabilities": [
    {
      "cve_id": "CVE-2024-XXXX",
      "severity": "HIGH",
      "description": "...",
      "affected_service": "...",
      "cvss_score": 7.5
    }
  ]
}
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `NVD_API_KEY` | API key for NVD database access | Yes |
| `SCAN_TIMEOUT` | Timeout for network scans (seconds) | No |
| `MAX_THREADS` | Maximum number of parallel threads | No |
| `OUTPUT_DIR` | Directory for scan results | No |

### API Keys

To obtain an NVD API key:

1. Visit the [NVD API website](https://nvd.nist.gov/developers/request-an-api-key)
2. Request an API key
3. Add the key to your `.env` file

## 🛡️ Security Considerations

### Ethical Usage

**IMPORTANT**: This tool should only be used for:
- Security assessments of systems you own
- Authorized penetration testing
- Educational purposes in controlled environments
- Security research with proper permissions

### Legal Notice

Unauthorized scanning of systems you do not own or have explicit permission to test may be illegal in your jurisdiction. Users are solely responsible for ensuring they have proper authorization before scanning any targets.

### Best Practices

- Always obtain written permission before scanning
- Document the scope of your testing
- Follow responsible disclosure practices
- Respect rate limits on APIs
- Avoid scanning production systems during peak hours

## 🤝 Contributing

Contributions are welcome! Please follow these guidelines:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Code Standards

- Follow PEP 8 style guidelines
- Include docstrings for functions and classes
- Add unit tests for new features
- Update documentation as needed

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🐛 Troubleshooting

### Common Issues

**Issue**: API rate limiting
- **Solution**: Reduce scan frequency or request a higher rate limit from NVD

**Issue**: Connection timeouts
- **Solution**: Increase the `SCAN_TIMEOUT` value in your `.env` file

**Issue**: Permission denied errors
- **Solution**: Ensure you have proper permissions and are running with appropriate privileges

**Issue**: Missing dependencies
- **Solution**: Re-run the setup script: `./setup.sh`

## 📚 Resources

- [NVD API Documentation](https://nvd.nist.gov/developers)
- [CVE Database](https://cve.mitre.org/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)

## 🔄 Changelog

### Version 1.0.0
- Initial release
- Parallel network scanning
- CVE detection via NVD API
- JSON output support

## 📧 Contact

For questions, suggestions, or issues, please:
- Open an issue on GitHub
- Contact the maintainer at [your-email@example.com]

## 🙏 Acknowledgments

- National Vulnerability Database (NVD) for CVE data
- Open-source security community
- All contributors to this project

---

**⚠️ Disclaimer**: This tool is provided "as is" without warranty of any kind. The authors are not responsible for any misuse or damage caused by this tool. Always ensure you have proper authorization before conducting security assessments.