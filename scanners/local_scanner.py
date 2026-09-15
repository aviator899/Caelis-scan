import os
import stat
import platform
from core.risk_engine import Finding

# Common sensitive files to check for overly permissive access
SENSITIVE_PATHS_UNIX = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/ssh/sshd_config",
]

def _is_world_writable(path):
    try:
        mode = os.stat(path).st_mode
        return bool(mode & stat.S_IWOTH)
    except (FileNotFoundError, PermissionError):
        return None  # can't check — file missing or no access

def scan_local():
    findings = []

    # 1. Check if running as root/admin
    try:
        is_admin = os.getuid() == 0 if platform.system() != "Windows" else False
        if is_admin:
            findings.append(Finding(
                "Root Privileges",
                "Scanner is running with root privileges",
                "Medium"
            ))
    except AttributeError:
        pass

    # 2. Check real file permissions on sensitive config files (Unix only)
    if platform.system() != "Windows":
        for path in SENSITIVE_PATHS_UNIX:
            result = _is_world_writable(path)
            if result is True:
                findings.append(Finding(
                    "Insecure File Permissions",
                    f"{path} is world-writable — any local user can modify it",
                    "High"
                ))
            elif result is False:
                findings.append(Finding(
                    "File Permissions OK",
                    f"{path} permissions look reasonable (not world-writable)",
                    "Info"
                ))
            # if None (file not found / no access), we skip silently rather than fake a result

    if not findings:
        findings.append(Finding(
            "Local Scan",
            "No local privilege or permission issues detected",
            "Info"
        ))

    return findings
