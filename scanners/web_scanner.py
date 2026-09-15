import requests
from core.risk_engine import Finding

def scan_web(url):
    findings = []
    try:
        response = requests.get(url, timeout=5)
        headers = response.headers

        # Check for critical security headers
        security_headers = ["Content-Security-Policy", "X-Frame-Options", "Strict-Transport-Security"]

        for header in security_headers:
            if header not in headers:
                findings.append(Finding(f"Missing {header}", f"The website is missing the {header} header, increasing risk of XSS/Clickjacking", "Risky"))

    except Exception as e:
        findings.append(Finding("Connection Error", f"Could not connect to {url}: {e}", "Very Risky"))

    return findings
