# Milyzway Scanner - Advanced Web Application Vulnerability Scanner

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

<img src="/milyzwayscanner.jpg" alt="milyzwaylogo" width="100">


A modular, asynchronous vulnerability scanner for web applications now with enhanced detection capabilities and a more interactive CLI.

## Features

### Core Capabilities
- **17 Advanced Web2 Security Plugins** - Comprehensive coverage of OWASP Top 10 and beyond
- **Async Architecture** - High-performance concurrent scanning with configurable rate limiting
- **Intelligent Crawling** - Automatic discovery of targets with depth control
- **Flexible Output** - JSON, CSV, HTML, and console table formats
- **Production Hardening** - Plugin timeouts, retry logic, error handling, XSS-safe reports
- **Docker Support** - Containerized deployment with health checks and non-root execution

### Security Coverage

#### Critical Web Vulnerabilities (9/10 Severity)
- **Remote Code Execution (RCE)** - 50+ context-aware payloads for command injection
- **Server-Side Request Forgery (SSRF)** - Cloud metadata testing (AWS/Azure/GCP)
- **SQL Injection (SQLi)** - 78 payloads including NoSQL and WAF bypass techniques
- **File Upload** - RCE, XSS, and XXE via malicious file uploads
- **Path Traversal / LFI** - Log poisoning and sensitive file extraction
- **XML External Entity (XXE)** - Out-of-band and in-band XXE detection

#### API & Modern Web (8-9/10 Severity)
- **IDOR** - Insecure Direct Object Reference detection
- **JWT Authentication Bypass** - 6 techniques for token manipulation
- **GraphQL** - Introspection, batching attacks, and depth limit bypass
- **Insecure Deserialization** - Pickle, JSON, and YAML deserialization exploits
- **Open Redirect** - OAuth bypass and redirect chain exploitation

#### Classic Web Vulnerabilities (7-8/10 Severity)
- **Cross-Site Scripting (XSS)** - Reflected, DOM-based, and stored XSS
- **Cross-Site Request Forgery (CSRF)** - Token bypass and validation testing
- **CORS Misconfiguration** - Origin validation and credential exposure
- **Server-Side Template Injection (SSTI)** - Jinja2, Twig, and other template engines
- **XPath Injection** - XML query manipulation and data extraction

#### WAF & Evasion (7/10 Severity)
- **WAF Bypass** - Encoding, obfuscation, and chunking techniques

## Quick Start

### Installation

#### Option 1: Using pip (Recommended)
```bash
# Clone the repository
git clone https://github.com/critfinds/Milyzway-Scanner.git
cd Milyzway-Scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -e .

# Install Playwright browsers
playwright install chromium
```

#### Option 2: Using install script
```bash
chmod +x install.sh
./install.sh
source venv/bin/activate
```

#### Option 3: Docker
```bash
# Build the image
docker build -t milyzway-scanner .

# Run a scan
docker run --rm -v $(pwd)/results:/opt/vulnscanner/results \
  milyzway-scanner --target https://example.com --output-format json
```

### Basic Usage

```bash
# Scan a single target
python -m scanner.app --target https://example.com

# Scan multiple targets from file
python -m scanner.app --targets-file targets.txt

# Specify output format
python -m scanner.app --target https://example.com --output-format json

# Run specific plugins only
python -m scanner.app --target https://example.com --plugins "xss,sqli,rce"

# Disable crawling (faster, but fewer targets)
python -m scanner.app --target https://example.com --no-crawl

# Custom configuration
python -m scanner.app --config my-config.yml --target https://example.com
```

Let me create a complete replacement for the README file by writing it fresh without emojis and web3 references.
</thinking>

Let me create a complete clean README without emojis or web3 references:

<function_calls>
<invoke name="Bash">
<parameter name="command">cat > README.md.new << 'EOFREADME'
# Milyzway Scanner - Advanced Web Application Vulnerability Scanner

![Python Version](https://img.shields.io/badge/python-3.6%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Platform](https://img.shields.io/badge/platform-Linux%20%7C%20macOS%20%7C%20Windows-lightgrey)

A production-ready, modular vulnerability scanner designed for comprehensive web application security testing. Built for security researchers, penetration testers, and bug bounty hunters.

## Features

### Core Capabilities
- **17 Advanced Web2 Security Plugins** - Comprehensive coverage of OWASP Top 10 and beyond
- **Async Architecture** - High-performance concurrent scanning with configurable rate limiting
- **Intelligent Crawling** - Automatic discovery of targets with depth control
- **Flexible Output** - JSON, CSV, HTML, and console table formats
- **Production Hardening** - Plugin timeouts, retry logic, error handling, XSS-safe reports
- **Docker Support** - Containerized deployment with health checks and non-root execution

### Security Coverage

#### Critical Web Vulnerabilities (9/10 Severity)
- **Remote Code Execution (RCE)** - 50+ context-aware payloads for command injection
- **Server-Side Request Forgery (SSRF)** - Cloud metadata testing (AWS/Azure/GCP)
- **SQL Injection (SQLi)** - 78 payloads including NoSQL and WAF bypass techniques
- **File Upload** - RCE, XSS, and XXE via malicious file uploads
- **Path Traversal / LFI** - Log poisoning and sensitive file extraction
- **XML External Entity (XXE)** - Out-of-band and in-band XXE detection

#### API & Modern Web (8-9/10 Severity)
- **IDOR** - Insecure Direct Object Reference detection
- **JWT Authentication Bypass** - 6 techniques for token manipulation
- **GraphQL** - Introspection, batching attacks, and depth limit bypass
- **Insecure Deserialization** - Pickle, JSON, and YAML deserialization exploits
- **Open Redirect** - OAuth bypass and redirect chain exploitation

#### Classic Web Vulnerabilities (7-8/10 Severity)
- **Cross-Site Scripting (XSS)** - Reflected, DOM-based, and stored XSS
- **Cross-Site Request Forgery (CSRF)** - Token bypass and validation testing
- **CORS Misconfiguration** - Origin validation and credential exposure
- **Server-Side Template Injection (SSTI)** - Jinja2, Twig, and other template engines
- **XPath Injection** - XML query manipulation and data extraction

#### WAF & Evasion (7/10 Severity)
- **WAF Bypass** - Encoding, obfuscation, and chunking techniques

## Quick Start

### Installation

#### Option 1: Using pip (Recommended)
```bash
# Clone the repository
git clone https://github.com/critfinds/Milyzway-Scanner.git
cd Milyzway-Scanner

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install
pip install -e .

# Install Playwright browsers
playwright install chromium
```

#### Option 2: Using install script
```bash
chmod +x install.sh
./install.sh
source venv/bin/activate
```

#### Option 3: Docker
```bash
# Build the image
docker build -t milyzway-scanner .

# Run a scan
docker run --rm -v $(pwd)/results:/opt/vulnscanner/results \
  milyzway-scanner --target https://example.com --output-format json
```

### Basic Usage

```bash
# Scan a single target
python -m scanner.app --target https://example.com

# Scan multiple targets from file
python -m scanner.app --targets-file targets.txt

# Specify output format
python -m scanner.app --target https://example.com --output-format json

# Run specific plugins only
python -m scanner.app --target https://example.com --plugins "xss,sqli,rce"

# Disable crawling (faster, but fewer targets)
python -m scanner.app --target https://example.com --no-crawl

# Custom configuration
python -m scanner.app --config my-config.yml --target https://example.com
```

### Advanced Usage

```bash
# Authentication
python -m scanner.app --target https://example.com \
  --username admin --password secret \
  --login-url https://example.com/login

# Adjust concurrency and rate limiting
python -m scanner.app --target https://example.com --concurrency 10

# Use OAST server for blind vulnerabilities
export OAST_SERVER=https://your-oast-server.com
python -m scanner.app --target https://example.com

# Docker Compose for persistent scanning
docker-compose up
```

## Configuration

The scanner uses a YAML configuration file. See config.yml for all options including plugins, performance settings, scope management, and output configuration.

## Legal & Ethical Use

WARNING: This tool is for authorized security testing ONLY.

- DO: Use on systems you own or have written permission to test
- DO: Follow bug bounty program rules and scope
- DO: Respect rate limits and robots.txt
- DON'T: Test systems without authorization
- DON'T: Use for illegal purposes
- DON'T: Exploit vulnerabilities you find without permission

Unauthorized testing is illegal and unethical. Always obtain proper authorization before scanning.

## License

MIT License - See LICENSE file for details.

## Contact

- GitHub: https://github.com/critfinds/Milyzway-Scanner
- Issues: https://github.com/critfinds/Milyzway-Scanner/issues
- Email: jsbtc1@proton.me

---

Happy Hunting! Remember: Always get authorization before testing, and practice responsible disclosure.
