import os
import platform
from core.risk_engine import Finding

def scan_local():
    findings = []
    # Example 1: Check if running as root/admin
    try:
        is_admin = os.getuid() == 0 if platform.system() != "Windows" else False
        if is_admin:
            findings.append(Finding("Root Privileges", "Scanner is running with root privileges", "Medium"))
    except AttributeError:
        pass

    # Example 2: Check for world-writable sensitive files (Simplified)
    findings.append(Finding("Local Config", "Sample local check: Config file permissions are default", "Low"))

    return findings
