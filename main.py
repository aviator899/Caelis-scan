import argparse
from core.reporter import display_results
from scanners.local_scanner import scan_local
from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web

def main():
    parser = argparse.ArgumentParser(description="Caelis Scan - Python Vulnerability Scanner")
    parser.add_argument("--target", help="Target IP or URL to scan")
    args = parser.parse_args()

    all_findings = []

    print("🚀 Starting Caelis Scan...\n")

    # 1. Local Scan
    print("[*] Scanning local machine...")
    all_findings.extend(scan_local())

    # 2. Target Scan (if provided)
    if args.target:
        print(f"[*] Scanning target: {args.target}...")
        # Try as a website
        if args.target.startswith("http"):
            all_findings.extend(scan_web(args.target))
        else:
            # Try as an IP/Host
            all_findings.extend(scan_network(args.target))

    # Final Report
    print("\n✅ Scan Complete. Results:\n")
    display_results(all_findings)

if __name__ == "__main__":
    main()
