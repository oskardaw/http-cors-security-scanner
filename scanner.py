import argparse
import sys
import requests
from urllib.parse import urlparse

SECURITY_HEADERS = [
    'Strict-Transport-Security',
    'Content-Security-Policy',
    'X-Frame-Options',
    'X-Content-Type-Options',
    'Referrer-Policy'
]

def check_cors(url, headers):
    findings = []
    origin = "https://evil-attacker.com"
    custom_headers = {'Origin': origin}
    
    try:
        r = requests.get(url, headers=custom_headers, timeout=5, verify=False)
        acao = r.headers.get('Access-Control-Allow-Origin')
        acac = r.headers.get('Access-Control-Allow-Credentials')
        
        if acao == '*':
            findings.append("[!] CORS: Access-Control-Allow-Origin is set to wildcard (*)")
            if acac == 'true':
                findings.append("[CRITICAL] CORS: Wildcard origin allowed with credentials!")
        elif acao == origin:
            findings.append(f"[!] CORS: Origin reflection detected for {origin}")
            if acac == 'true':
                findings.append("[CRITICAL] CORS: Arbitrary Origin reflected with credentials allowed!")
        elif acao == 'null':
            findings.append("[!] CORS: 'null' Origin allowed in Access-Control-Allow-Origin")
            
    except requests.exceptions.RequestException as e:
        findings.append(f"[-] CORS check failed: {e}")
        
    return findings

def check_missing_headers(headers):
    missing = []
    for h in SECURITY_HEADERS:
        if h not in headers and h.lower() not in [k.lower() for k in headers.keys()]:
            missing.append(h)
    return missing

def scan_target(target_url):
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'https://' + target_url
        
    print(f"[*] Scanning target: {target_url}\n")
    
    try:
        res = requests.get(target_url, timeout=5, verify=False)
    except requests.exceptions.RequestException as e:
        print(f"[-] Error connecting to {target_url}: {e}")
        sys.exit(1)
        
    print("[+] Missing Security Headers:")
    missing = check_missing_headers(res.headers)
    if missing:
        for m in missing:
            print(f"  - {m}")
    else:
        print("  + All key security headers are present")
        
    print("\n[+] CORS Analysis:")
    cors_results = check_cors(target_url, res.headers)
    if cors_results:
        for c in cors_results:
            print(f"  {c}")
    else:
        print("  + No basic CORS misconfigurations detected")

if __name__ == '__main__':
    requests.packages.urllib3.disable_warnings()
    
    parser = argparse.ArgumentParser(description="HTTP Security Headers & CORS Misconfiguration Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL (e.g. https://example.com)")
    args = parser.parse_args()
    
    scan_target(args.url)
