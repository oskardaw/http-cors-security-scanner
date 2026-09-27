# HTTP Security Headers & CORS Misconfiguration Scanner

A lightweight Python command-line utility designed to analyze HTTP response headers for missing security configurations and test for potential CORS (Cross-Origin Resource Sharing) vulnerabilities.

## Features

- **Security Header Audit**: Checks for missing critical defense headers (`HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`).
- **CORS Misconfiguration Testing**:
  - Detects wildcard `Access-Control-Allow-Origin` headers paired with credentials.
  - Tests for arbitrary Origin reflection.
  - Identifies insecure `null` Origin trust relationships.

## Installation

```bash
git clone [https://github.com/oskardaw/http-cors-security-scanner.git](https://github.com/oskardaw/http-cors-security-scanner.git)
cd http-cors-security-scanner
pip install -r requirements.txt

python scanner.py -u [https://example.com](https://example.com)

[*] Scanning target: [https://example.com](https://example.com)

[+] Missing Security Headers:
  - Strict-Transport-Security
  - Content-Security-Policy
  - X-Frame-Options

[+] CORS Analysis:
  [!] CORS: Origin reflection detected for [https://evil-attacker.com](https://evil-attacker.com)
  [CRITICAL] CORS: Arbitrary Origin reflected with credentials allowed!
