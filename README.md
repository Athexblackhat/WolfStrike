<div align="center">

<img src="/logo.png" alt=" Unleash The Pack " width="500" height="auto">

</div>


# WOLFSTRIKE - Ultimate Web Penetration Testing Toolkit

<p align="center">
  <img src="https://img.shields.io/badge/Version-1.0.0-red?style=for-the-badge" alt="Version">
  <img src="https://img.shields.io/badge/Codename-Shadowfang-darkred?style=for-the-badge" alt="Codename">
  <img src="https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License">
  <img src="https://img.shields.io/badge/Platform-Cross%20Platform-orange?style=for-the-badge" alt="Platform">
  <img src="https://img.shields.io/badge/Total%20Features-160%2B-purple?style=for-the-badge" alt="Features">
  <img src="https://img.shields.io/badge/Lines%20of%20Code-47%2C511%2B-yellow?style=for-the-badge" alt="Code">
  <img src="https://img.shields.io/badge/Tests%20Passed-95%25-success?style=for-the-badge" alt="Tests">
</p>

<p align="center">
  <b>CREATED BY ATHEX BLACK HAT</b><br>
  <b>Team Wolf Intelligence PK</b><br>
  <b>Released: July 9, 2026</b>
</p>

---

## OVERVIEW

**WOLFSTRIKE** (Codename: Shadowfang) is a professional-grade, all-in-one web application penetration testing toolkit engineered for security professionals, ethical hackers, and penetration testers. Developed by **ATHEX BLACK HAT** under **Wolf Intelligence PK**, this tool integrates comprehensive reconnaissance, advanced vulnerability scanning, intelligent exploitation, and enterprise-ready reporting into a single, powerful command-line interface.

With **160+ features** across **9 major module categories**, WOLFSTRIKE represents the most complete offensive security toolkit ever assembled in a single codebase. From passive OSINT gathering to active exploitation, from AI-powered vulnerability detection to stealth proxy rotation, every aspect of a professional security assessment is covered.

---

## KEY FEATURES

### Reconnaissance Suite (12 Modules)
- Multi-source subdomain enumeration with passive APIs and DNS brute force
- Comprehensive WHOIS lookup with registrar and nameserver analysis
- Complete DNS record enumeration (A, AAAA, MX, NS, TXT, CNAME, SOA, SRV, CAA)
- Reverse IP lookup to discover co-hosted domains
- Email harvesting from public sources and web pages
- Social media account discovery across major platforms
- Cloud storage bucket discovery (AWS S3, GCP, Azure, DigitalOcean)
- Technology stack detection (200+ signatures across web servers, frameworks, CMS)
- Web Application Firewall (WAF) detection and identification
- Content Delivery Network (CDN) detection with origin IP discovery
- SSL/TLS certificate analysis with vulnerability assessment
- Robots.txt and Sitemap.xml analysis for hidden endpoint discovery

### Network & Web Scanner (10 Modules)
- Multi-threaded TCP/UDP port scanner with banner grabbing
- Service version detection with protocol-specific fingerprinting
- Operating system detection via TTL analysis and HTTP headers
- HTTP methods testing (GET, POST, PUT, DELETE, PATCH, OPTIONS, TRACE)
- Security header analysis with compliance checking
- Cookie security analyzer with attribute validation
- JavaScript analysis for secrets, endpoints, and dangerous patterns
- Hidden form field discovery for sensitive parameter exposure
- API endpoint discovery via common path enumeration
- Backup file finder for exposed configuration and database backups

### Vulnerability Scanner (15 Modules)
- Cross-Site Scripting (XSS) - Reflected, Stored, and DOM-based detection
- SQL Injection - Error-based, Boolean-based, and Time-based detection
- NoSQL Injection - MongoDB, CouchDB, and Firebase injection testing
- Command Injection - OS command injection via multiple separators
- LDAP Injection - LDAP metacharacter and filter injection
- XPath Injection - XPath query manipulation and boolean-based detection
- Server-Side Template Injection (SSTI) - Jinja2, Twig, Freemarker, Velocity
- Server-Side Request Forgery (SSRF) - Internal and cloud metadata access
- Local File Inclusion (LFI) - Path traversal and PHP wrapper injection
- Remote File Inclusion (RFI) - Remote URL and protocol injection
- Cross-Site Request Forgery (CSRF) - Anti-CSRF token validation
- Open Redirect - Parameter-based redirect manipulation
- File Upload - Unrestricted file type and extension testing
- Clickjacking - X-Frame-Options and CSP frame-ancestors validation
- CORS Misconfiguration - Origin reflection and credential exposure
- Security Misconfiguration - Default credentials, debug modes, admin panels

### Attack & Exploitation (10 Modules)
- SQL Injection exploitation with union, error, boolean, and time-based techniques
- XSS exploitation for session hijacking and credential harvesting
- JWT attacks including none algorithm, algorithm confusion, and weak secret
- Deserialization attacks (PHP, Java, Python, .NET)
- Race condition testing with concurrent request analysis
- Host header injection for password reset poisoning and cache poisoning
- CRLF injection for HTTP response splitting and header injection
- Web cache poisoning via header manipulation
- Prototype pollution in JavaScript applications
- CSS injection for data exfiltration and content manipulation

### Authentication Testing (6 Modules)
- Brute force attack testing with rate limiting and lockout detection
- Password policy validation with complexity and length analysis
- Session management testing including fixation, timeout, and logout
- JWT token security analysis with claim validation
- OAuth 2.0 implementation testing for CSRF and redirect bypass
- Multi-Factor Authentication (MFA) bypass testing

### Web Crawler & Spider (5 Modules)
- Advanced web spider with configurable depth and scope
- AJAX/JavaScript crawler for single-page applications
- Sitemap generator and analyzer for URL discovery
- Broken link checker with redirect chain analysis
- Wayback Machine integration for historical URL retrieval

### API Security Testing (7 Modules)
- REST API testing for authentication, authorization, and input validation
- GraphQL introspection, depth attack, and injection testing
- SOAP/WSDL web service vulnerability assessment
- Rate limiting detection and bypass testing
- Mass assignment vulnerability testing
- Broken Object Level Authorization (BOLA) testing
- Broken Function Level Authorization (BFLA) testing

### Network Security (5 Modules)
- Email security configuration (SPF, DKIM, DMARC, MX, BIMI)
- DNSSEC validation and configuration analysis
- DNS zone transfer vulnerability testing
- ASN lookup and IP range analysis
- BGP routing information gathering

### OSINT Integration (7 Modules)
- Shodan API integration for exposed service discovery
- Censys API integration for certificate and host search
- SecurityTrails API for DNS history and subdomain enumeration
- Certificate Transparency log analysis for subdomain discovery
- GitHub dork scanner for exposed secrets and credentials
- Pastebin monitor for leaked data detection
- Data breach verification via HaveIBeenPwned API

### AI-Powered Detection Engine
- Pattern recognition with 30+ built-in vulnerability signatures
- Context-aware smart payload generation
- False positive detection and filtering system
- Application behavior analysis and profiling
- Statistical anomaly detection with multiple methods
- ML-based risk scoring with CVSS methodology

### Stealth & Evasion
- Proxy rotation with HTTP, HTTPS, and SOCKS5 support
- User-Agent rotation with 50+ real browser signatures
- Intelligent rate limiting with adaptive delays
- CAPTCHA detection and bypass strategy generation
- Request randomization to avoid fingerprinting
- TOR network routing with automatic circuit renewal

### Professional Reporting
- PDF report generation with severity charts and executive summary
- Interactive HTML dashboard with collapsible findings
- JSON export for tool integration and automation
- Terminal-based real-time report display
- MITRE ATT&CK framework mapping
- CVSS-based risk score calculation
- Detailed remediation guidance with step-by-step instructions

### Integrations
- Slack webhook notifications for scan alerts
- Telegram bot integration for real-time updates
- Discord webhook for team collaboration
- JIRA ticket creation for vulnerability tracking
- CI/CD pipeline integration with configurable failure criteria

---

## INSTALLATION

### Linux (Recommended for Full Power)

```
git clone https://github.com/Athexblackhat/WolfStrike.git
cd WolfStrike
bash installers/install.sh
```


### One-Line Install (Linux)

```
curl -sSL https://raw.githubusercontent.com/Athexblackhat/WolfStrike/main/installers/install.sh |
```

### Windows
```
git clone https://github.com/Athexblackhat/WolfStrike.git
cd WolfStrike
installers\install_windows.bat
```

### macOS
```
git clone https://github.com/Athexblackhat/WolfStrike.git
cd WolfStrike
bash installers/install_mac.sh
```
### Termux (Android - Lite Mode)
```
git clone https://github.com/Athexblackhat/WolfStrike.git
cd WolfStrike
bash installers/install_termux.sh
```
### Docker
```
docker build -t wolfstrike .
docker run -it --rm wolfstrike --target example.com
```
### Manual Installation
```
git clone https://github.com/Athexblackhat/WolfStrike.git
cd WolfStrike
pip install -r requirements.txt
python setup.py install
```



## Set Your Env
```
cp .env.example .env

nano .env
```

## CONFIGURATION

```

# Shodan API Key (for OSINT module)
SHODAN_API_KEY=your_shodan_api_key_here

# Censys API Keys
CENSYS_API_ID=your_censys_api_id_here
CENSYS_API_SECRET=your_censys_api_secret_here

# SecurityTrails API Key
SECURITYTRAILS_API_KEY=your_securitytrails_api_key_here

# GitHub Token (for dorking, optional)
GITHUB_TOKEN=your_github_token_here

# Proxy Configuration (optional)
HTTP_PROXY=
HTTPS_PROXY=
SOCKS_PROXY=

# TOR Configuration
TOR_PORT=9050
TOR_CONTROL_PORT=9051

# Notification Webhooks (optional)
SLACK_WEBHOOK_URL=
DISCORD_WEBHOOK_URL=
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=

# Default Settings
DEFAULT_THREADS=50
DEFAULT_TIMEOUT=30
DEFAULT_USER_AGENT=Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0

# Logging
LOG_LEVEL=INFO
DEBUG_MODE=false

# Output Directory
OUTPUT_DIR=./reports
```


## QUICK START

### Basic scan
```
wolfstrike --target example.com
```
### Full power scan with all modules
```
wolfstrike --target example.com --full-power
```
### Interactive menu mode
```
wolfstrike --interactive
```
### Specific module scan
```
wolfstrike --target example.com --module sqli,xss,lfi
```
### Stealth scan through TOR
```
wolfstrike --target example.com --stealth --tor
```
### Generate PDF report
```
wolfstrike --target example.com --report pdf --output ./audit/
```
### Verbose debug mode
```
wolfstrike --target example.com --verbose --debug
```
### Scan with custom threads and timeout
```
wolfstrike --target example.com --threads 100 --timeout 15
```

## COMMAND-LINE OPTIONS
Option               | Description
---------------------|------------------------
-t, --target URL     | Target URL or IP address
-f, --file FILE      | File containing list of targets
--quick              | Quick scan with default settings
--full-power         | Full power scan with all modules
--interactive        | Launch interactive menu mode
-m, --module MODS    | Comma-separated modules to run
--exclude-module MODS| Modules to exclude
--stealth            | Enable stealth mode
--tor                | Route traffic through TOR
--proxy URL          | Use proxy server
--random-agent       | Random User-Agent per request
--user-agent AGENT   | Custom User-Agent string
--threads N          | Concurrent threads (default: 50)
--timeout SEC        | Request timeout (default: 30)
--delay SEC          | Request delay (default: 0)
--retries N          | Request retries (default: 3)
--max-depth N        | Crawl depth (default: 3)
-o, --output DIR     | Output directory
--report FORMAT      | Report format (pdf/html/json/all)
-v, --verbose        | Verbose output
--debug              | Debug mode
-q, --quiet          | Quiet mode
--no-color           | Disable colored output
--waf-bypass         | Enable WAF bypass techniques
--ai-engine          | Enable AI detection engine
--no-ai              | Disable AI detection engine
--config FILE        | Load configuration file
--cookie COOKIE      | Add cookie (name=value)
--header HEADER      | Add custom header (Name: Value)
--auth USER:PASS     | Basic authentication
--version            | Show version information
--banner             | Display the WOLFSTRIKE banner
--list-modules       | List all available modules
-h, --help           | Show help message


## MODULE CATEGORIES
Category       | Modules | Description
---------------|---------|------------
recon          | 12      | Subdomain, WHOIS, DNS, Technology, WAF, CDN, SSL
scanner        | 10      | Port, Service, OS, HTTP Methods, Headers, Cookies, JS
vuln_scanner   | 15      | XSS, SQLi, NoSQLi, Command, LDAP, XPath, SSTI, SSRF, LFI/RFI, CSRF
attacks        | 10      | SQLi Exploit, XSS Exploit, JWT, Deserialization, Race Condition
auth_tester    | 6       | Brute Force, Password Policy, Session, JWT, OAuth, MFA
crawler        | 5       | Spider, AJAX Crawler, Sitemap, Link Checker, Wayback Machine
api_tester     | 7       | REST, GraphQL, SOAP, Rate Limit, Mass Assignment, BOLA, BFLA
network        | 5       | Email Security, DNSSEC, Zone Transfer, ASN, BGP
osint          | 7       | Shodan, Censys, SecurityTrails, Cert Logs, GitHub, Pastebin, Breach


## PLATFORM SUPPORT
Platform          | Status       | Features
------------------|--------------|------------------
Kali Linux        | Full Support | 160+ Features
Parrot OS         | Full Support | 160+ Features
Ubuntu/Debian     | Full Support | 160+ Features
Arch Linux        | Full Support | 160+ Features
Fedora/RHEL       | Full Support | 160+ Features
Windows 10/11     | Full Support | 160+ Features
macOS             | Full Support | 160+ Features
Termux (Android)  | Lite Mode    | 40+ Core Features
Docker            | Full Support | 160+ Features
Cloud VPS         | Full Support | 160+ Features

## SECURITY
WOLFSTRIKE is designed for authorized security testing only. Users are responsible for complying with all applicable laws and regulations. The authors assume no liability for misuse or damage caused by this tool.


## DISCLAIMER
This tool is intended for:

Authorized penetration testing

Security assessments on owned systems

Educational purposes

Bug bounty programs with explicit permission

DO NOT USE THIS TOOL ON SYSTEMS YOU DO NOT OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST.

### CREDITS

<p align="center"> <b>CREATED BY ATHEX BLACK HAT</b><br> <b>Team Wolf Intelligence PK</b><br> <b>Version 1.0.0 (Shadowfang)</b><br> <b>Released July 9, 2026</b> </p>

Copyright (c) 2026 Wolf Intelligence PK

<p align="center"> <b>WOLFSTRIKE - Unleash the Pack, Strike the Shadows</b><br> <b>CREATED BY ATHEX BLACK HAT | Wolf Intelligence PK</b> </p>
