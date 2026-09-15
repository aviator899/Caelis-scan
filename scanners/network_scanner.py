import socket
from core.risk_engine import Finding

def scan_network(target):
    findings = []
    # Common ports to check
    common_ports = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 3389: "RDP"}

    for port, service in common_ports.items():
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((target, port))
        if result == 0:
            risk = "Medium" if service in ["FTP", "RDP"] else "Low"
            findings.append(Finding(f"Open Port {port}", f"{service} service is accessible", risk))
        sock.close()

    return findings
