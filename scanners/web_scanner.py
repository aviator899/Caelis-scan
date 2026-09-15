import requests
from urllib.parse import urlparse
from core.risk_engine import Finding
from core.crawler import crawl
from core.cve_lookup import lookup_cves
from scanners.xss_scanner import scan_reflected_xss


def _scan_single_page(url, timeout=5):
    """Header/cookie/HTTPS checks for one URL. Returns (findings, detected_software_strings)."""
    findings = []
    detected_software = set()

    try:
        response = requests.get(url, timeout=timeout, allow_redirects=True)
        headers = response.headers

        security_headers = {
            "Content-Security-Policy": "increases risk of XSS/data injection",
            "X-Frame-Options": "increases risk of Clickjacking",
            "Strict-Transport-Security": "allows downgrade to insecure HTTP",
            "X-Content-Type-Options": "allows MIME-sniffing attacks",
            "Referrer-Policy": "may leak full URL/path to third parties",
            "Permissions-Policy": "no restriction on browser feature access",
        }
        for header, risk_desc in security_headers.items():
            if header not in headers:
                findings.append(Finding(
                    f"Missing {header}",
                    f"The site is missing the {header} header — {risk_desc}",
                    "Risky"
                ))

        if "X-Frame-Options" in headers:
            val = headers["X-Frame-Options"].upper()
            if val not in ("DENY", "SAMEORIGIN"):
                findings.append(Finding(
                    "Weak X-Frame-Options",
                    f"X-Frame-Options is set to '{headers['X-Frame-Options']}', which may not block framing",
                    "Medium"
                ))

        if "Strict-Transport-Security" in headers:
            hsts = headers["Strict-Transport-Security"]
            if "max-age=0" in hsts.replace(" ", ""):
                findings.append(Finding(
                    "HSTS Disabled",
                    "Strict-Transport-Security is present but max-age=0 disables it",
                    "Risky"
                ))

        for leaky_header in ("Server", "X-Powered-By", "X-AspNet-Version"):
            if leaky_header in headers:
                value = f"{leaky_header}: {headers[leaky_header]}"
                findings.append(Finding(
                    f"{leaky_header} Disclosure",
                    f"{value} — reveals server/framework version to attackers",
                    "Low"
                ))
                detected_software.add(headers[leaky_header])  # normalized value, not full sentence

        for cookie in response.cookies:
            issues = []
            if not cookie.secure:
                issues.append("missing Secure flag")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                issues.append("missing HttpOnly flag")
            if issues:
                findings.append(Finding(
                    f"Insecure Cookie: {cookie.name}",
                    f"Cookie '{cookie.name}' is {', '.join(issues)}",
                    "Medium"
                ))

        parsed = urlparse(url)
        if parsed.scheme == "http":
            findings.append(Finding(
                "No HTTPS",
                "Site was scanned over plain HTTP — traffic is unencrypted",
                "Very Risky"
            ))
        elif response.url.startswith("http://"):
            findings.append(Finding(
                "HTTPS Redirect Missing",
                "Site did not redirect HTTP requests to HTTPS",
                "Risky"
            ))

    except requests.exceptions.SSLError as e:
        findings.append(Finding("SSL Error", f"TLS/certificate problem connecting to {url}: {e}", "Very Risky"))
    except requests.exceptions.ConnectionError as e:
        findings.append(Finding("Connection Error", f"Could not connect to {url}: {e}", "Very Risky"))
    except requests.exceptions.Timeout:
        findings.append(Finding("Timeout", f"{url} did not respond within 5 seconds", "Medium"))
    except Exception as e:
        findings.append(Finding("Scan Error", f"Unexpected error scanning {url}: {e}", "Very Risky"))

    return findings, detected_software


def scan_web(url, max_pages=25, do_crawl=True, do_cve=True):
    """
    Full web scan pipeline for a target URL:
    crawl same-domain pages -> header/cookie/HTTPS checks per page ->
    reflected-input checks per page -> CVE lookup on fingerprinted software.
    """
    all_findings = []
    all_detected_software = set()

    urls_to_scan = [url]
    if do_crawl:
        discovered = crawl(url, max_pages=max_pages)
        urls_to_scan = discovered or urls_to_scan

    for page_url in urls_to_scan:
        page_findings, software = _scan_single_page(page_url)
        all_findings.extend(page_findings)
        all_detected_software.update(software)

        xss_findings = scan_reflected_xss(page_url)
        all_findings.extend(xss_findings)

    if do_cve and all_detected_software:
        for banner in all_detected_software:
            all_findings.extend(lookup_cves(banner))

    if not all_findings:
        all_findings.append(Finding(
            "Web Scan",
            f"No common header/cookie/HTTPS/XSS issues detected on {url}",
            "Info"
        ))

    return all_findings
