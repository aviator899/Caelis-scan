import socket
import concurrent.futures
from core.risk_engine import Finding

# Known services for common ports — used for labeling when we can't grab a banner
COMMON_PORTS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 69: "TFTP", 80: "HTTP", 110: "POP3",
    111: "RPCbind", 123: "NTP", 135: "MSRPC", 137: "NetBIOS", 139: "NetBIOS-SSN",
    143: "IMAP", 161: "SNMP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP-Submission",
    631: "IPP", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    2375: "Docker", 2376: "Docker-TLS", 3000: "Dev-Server", 3306: "MySQL",
    3389: "RDP", 5000: "Dev-Server", 5432: "PostgreSQL", 5601: "Kibana",
    5900: "VNC", 5984: "CouchDB", 6379: "Redis", 7001: "WebLogic",
    8000: "HTTP-Alt", 8080: "HTTP-Proxy", 8443: "HTTPS-Alt", 8888: "HTTP-Alt",
    9000: "Dev-Server", 9200: "Elasticsearch", 11211: "Memcached",
    27017: "MongoDB",
}

# Ports where an open connection is inherently risky, regardless of banner
HIGH_RISK_PORTS = {
    21, 23, 111, 135, 139, 445, 512, 513, 514, 1433, 1521, 2375, 2376,
    3306, 3389, 5432, 5900, 5984, 6379, 7001, 9200, 11211, 27017,
}

MAX_WORKERS = 200
CONNECT_TIMEOUT = 0.75
BANNER_TIMEOUT = 1.0


def _grab_banner(sock):
    """Try to read a banner without sending anything first (works for FTP, SSH, SMTP, etc.)."""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        data = sock.recv(256)
        if data:
            return data.decode(errors="ignore").strip().split("\n")[0][:120]
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    return None


def _probe_http(sock, target, port):
    """If banner-grab found nothing, try a minimal HTTP request — many web servers stay silent until spoken to."""
    try:
        sock.settimeout(BANNER_TIMEOUT)
        req = f"HEAD / HTTP/1.1\r\nHost: {target}\r\nConnection: close\r\n\r\n"
        sock.sendall(req.encode())
        data = sock.recv(512).decode(errors="ignore")
        for line in data.split("\r\n"):
            if line.lower().startswith("server:"):
                return line.strip()
        if data.startswith("HTTP/"):
            return data.split("\r\n")[0]
    except (socket.timeout, ConnectionResetError, OSError):
        pass
    return None


def _scan_port(target, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.settimeout(CONNECT_TIMEOUT)
        result = sock.connect_ex((target, port))
        if result != 0:
            return None  # closed / filtered

        service = COMMON_PORTS.get(port, "Unknown")
        banner = _grab_banner(sock)
        if not banner and port in (80, 8080, 8000, 8888, 3000, 5000, 9000):
            banner = _probe_http(sock, target, port)

        risk = "Medium" if port in HIGH_RISK_PORTS else "Low"
        detail = f"{service} service is accessible on port {port}"
        if banner:
            detail += f" — banner: {banner}"

        return Finding(f"Open Port {port}", detail, risk)
    except (socket.timeout, OSError):
        return None
    finally:
        sock.close()


def scan_network(target, port_range=(1, 65535)):
    findings = []
    start, end = port_range
    ports = range(start, end + 1)

    with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {executor.submit(_scan_port, target, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                findings.append(result)

    if not findings:
        findings.append(Finding(
            "Network Scan",
            f"No open ports detected on {target} in scanned range ({start}-{end})",
            "Info"
        ))

    return findings
