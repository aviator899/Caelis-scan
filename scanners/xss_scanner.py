# scanners/xss_scanner.py
import requests
import uuid
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from core.risk_engine import Finding

def scan_reflected_xss(url, timeout=5):
    """
    Checks each query parameter by injecting a unique marker string and
    seeing if it comes back unescaped in the response body. This detects
    the *precondition* for reflected XSS (unescaped reflection) without
    sending any actual script payload.
    """
    findings = []
    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    if not params:
        return findings  # nothing to test on this URL

    for param in params:
        marker = f"caelis{uuid.uuid4().hex[:8]}"
        test_params = params.copy()
        test_params[param] = marker
        test_query = urlencode(test_params, doseq=True)
        test_url = urlunparse(parsed._replace(query=test_query))

        try:
            resp = requests.get(test_url, timeout=timeout)
            if marker in resp.text:
                # Reflected unescaped — check if it landed inside a risky context
                idx = resp.text.find(marker)
                snippet = resp.text[max(0, idx - 20):idx + len(marker) + 20]
                findings.append(Finding(
                    f"Reflected Input: {param}",
                    f"Parameter '{param}' is reflected unescaped in the response "
                    f"(context: ...{snippet}...) — possible reflected XSS, needs manual confirmation",
                    "Risky"
                ))
        except requests.RequestException:
            continue

    return findings
