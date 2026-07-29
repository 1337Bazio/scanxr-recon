ScanXr Recon Tool

Python reconnaissance and security assessment tool for authorized targets.

ScanXr is a Python-based web reconnaissance tool designed to collect basic information about a website and identify potential security weaknesses.

The tool performs several automated checks, including:

* Target IP resolution
* SSL certificate information
* Technology detection
* HTTP security header analysis
* Cookie inspection
* Authentication surface discovery
* JavaScript file extraction and analysis
* Common path enumeration
* Reflected parameter checks
* Basic IDOR response comparison
* JSON report generation
* Risk score calculation

Warning: This tool is intended for educational purposes and authorized security testing only. Only scan websites, applications, servers, or systems that you own or have explicit permission to test.

⸻

Features

Reconnaissance

ScanXr collects basic information about the target:

* Domain name
* Resolved IP address
* Website title
* SSL certificate issuer
* SSL certificate expiration
* Detected web technologies

Technology Detection

The current version attempts to identify:

* React
* Vue
* Angular
* Laravel
* WordPress
* Nginx
* Apache

Technology detection is based on simple signatures and may produce false positives or miss technologies.

Security Header Checks

The tool checks for the following HTTP security headers:

* Content-Security-Policy
* X-Frame-Options
* X-Content-Type-Options
* Strict-Transport-Security
* Referrer-Policy

Missing headers are reported as potential security findings.

Cookie Analysis

ScanXr extracts cookies returned by the target and displays:

* Cookie name
* Secure flag
* HttpOnly flag

Authentication Surface Detection

The HTML source is checked for common authentication-related keywords:

* Login
* Logout
* Password reset

These results indicate possible authentication functionality and are not vulnerabilities by themselves.

Common Path Enumeration

The tool checks a small list of common paths, including:

/robots.txt
/sitemap.xml
/.env
/.git/HEAD
/admin
/login
/api
/graphql
/swagger.json
/backup
/debug
/.DS_Store

An accessible path does not automatically mean that the path is vulnerable. Results must be manually reviewed.

JavaScript Analysis

ScanXr extracts JavaScript files referenced by the target and looks for indicators such as:

* Possible API keys or secrets
* GraphQL references
* WebSocket endpoints
* Source map references
* API endpoint patterns

These checks are heuristic and may generate false positives.

Reflected Parameter Checks

The tool sends a harmless test value through a small list of common query parameters and checks whether the value appears in the response.

A reflected value does not automatically indicate an XSS vulnerability. Context-aware validation is required.

Basic IDOR Pattern Checks

The tool compares responses generated with several common object identifiers.

Examples:

?id=1
?id=2
?id=3
?id=10
?id=9999

The tool reports response differences, status changes, and size anomalies.

A response variation is not proof of an IDOR vulnerability. Proper IDOR testing requires authenticated accounts, authorization checks, and manual verification.

JSON Reports

After a scan, the results are exported to:

result.json

The report can contain:

* Target URL
* Domain
* IP address
* Cookies
* JavaScript files
* Discovered paths
* Reflected parameters
* Potential IDOR indicators
* Detected technologies
* SSL information
* Security findings
* Risk score

⸻

Requirements

* Python 3.8 or newer
* Python package:

requests

⸻

Installation

Clone the repository:

git clone https://github.com/1337bazio/ScanXr-Recon.git

Open the project directory:

cd ScanXr-Recon

Install the required dependency:

pip install requests

⸻

Usage

Run the Python script:

python scanxr.py

The tool will ask for the access key:

=== AUTH REQUIRED ===
Enter access key:

Then enter an authorized target:

TARGET URL: https://example.com

The tool accepts URLs with or without the protocol.

Examples:

https://example.com
http://example.com
example.com

⸻

Example

======================================================================
BAZIO SCAN RESULTS
======================================================================
Domain: example.com
IP: 93.184.216.34
Risk Score: 82/100
Classification: LOW RISK
Technologies:
 - Nginx
Cookies:
 - session
   (Secure=True HttpOnly=True)
======================================================================
DETAILED FINDINGS
======================================================================
[MEDIUM] Missing Security Headers
Target:
https://example.com
Details:
CSP missing
Description:
Important HTTP security headers are missing.
Impact:
Can increase exposure to XSS, clickjacking, or MIME attacks.
CWE:
CWE-693
Recommendation:
Add recommended HTTP security headers.

The output above is only an example. Actual results depend on the target.

⸻

Risk Score

ScanXr starts with a score of:

100/100

The score is reduced according to several detected indicators, including:

* Reflected parameters
* Accessible paths
* Security findings
* Cookies
* JavaScript files
* Potential IDOR response differences

The final score is classified as:

Score	Classification
80–100	LOW RISK
50–79	MEDIUM RISK
0–49	HIGH RISK

The score is an internal heuristic and should not be considered a formal security rating.

⸻

Project Structure

ScanXr-Recon/
│
├── scanxr.py
├── README.md
├── requirements.txt
├── .gitignore
└── result.json

Recommended requirements.txt:

requests>=2.31.0

Recommended .gitignore:

__pycache__/
*.py[cod]
.venv/
venv/
env/
result.json
.env

⸻

Limitations

ScanXr is a lightweight reconnaissance tool and is not a complete vulnerability scanner.

The tool may:

* Produce false positives
* Miss vulnerabilities
* Detect public resources that are intentionally accessible
* Report response differences that are expected application behavior
* Identify JavaScript keywords that are not real secrets
* Detect technologies incorrectly

All findings should be manually validated before being reported as security vulnerabilities.

⸻

Security and Responsible Use

Only use ScanXr against:

* Systems you own
* Local development environments
* Security labs
* Capture-the-Flag environments
* Applications covered by a bug bounty scope
* Targets for which you have explicit authorization

Do not use this tool to scan third-party systems without permission.

The author is not responsible for misuse or unauthorized testing.

⸻

Disclaimer

This project is provided for:

* Educational purposes
* Security research
* Authorized penetration testing
* Defensive security assessments

The software is provided without warranty. Use it responsibly and comply with all applicable laws, rules, and authorization requirements.

⸻

Roadmap

Possible future improvements:

* Command-line arguments
* Custom wordlists
* Configurable request timeout
* Configurable request rate
* HTML report generation
* CSV report export
* Improved technology fingerprints
* Better cookie security checks
* Redirect analysis
* HTTP method analysis
* Improved JavaScript endpoint extraction
* More accurate risk scoring
* Unit tests
* Docker support

⸻

Contributing

Contributions are welcome.

You can contribute by:

1. Forking the repository
2. Creating a feature branch
3. Making your changes
4. Testing the project
5. Opening a pull request

Please keep contributions focused on authorized and defensive security use.

⸻

License

Choose a license before publishing the repository.

For an open-source project, the MIT License is a simple option.

Example:

MIT License
Copyright (c) 2026 BAZIO
Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files, to deal in the Software
without restriction, including the rights to use, copy, modify, merge,
publish, distribute, sublicense, and sell copies of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.

⸻

Author

BAZIO

ScanXr Recon Tool — Python Web Reconnaissance and Security Assessment Tool.
