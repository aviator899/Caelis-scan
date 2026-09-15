# core/cve_lookup.py
import requests
import re
from core.risk_engine import Finding

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def _parse_product_version(banner_or_header):
    """Very rough extraction, e.g. 'Apache/2.4.49' -> ('apache', '2.4.49')."""
    match = re.search(r"([A-Za-z][A-Za-z0-9\-]+)[/ ]([\d]+\.[\d]+(?:\.[\d]+)?)", banner_or_header)
    if match:
        return match.group(1).lower(), match.group(2)
    return None, None

def lookup_cves(banner_or_header, max_results=3):
    findings = []
    product, version = _parse_product_version(banner_or_header)
    if not product:
        return findings

    try:
        resp = requests.get(
            NVD_API,
            params={"keywordSearch": f"{product} {version}", "resultsPerPage": max_results},
            timeout=8,
        )
        resp.raise_for_status()
        data = resp.json()

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]
            cve_id = cve["id"]
            desc = next(
                (d["value"] for d in cve.get("descriptions", []) if d["lang"] == "en"),
                "No description available"
            )
            findings.append(Finding(
                f"Potential {cve_id}",
                f"Detected {product} {version} matches known CVE: {desc[:150]}...",
                "Very Risky"
            ))
    except requests.RequestException:
        pass  # NVD API down/rate-limited — fail quietly, don't fabricate a result

    return findings
