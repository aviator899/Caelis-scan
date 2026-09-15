import argparse
from core.reporter import display_results
from scanners.local_scanner import scan_local
from scanners.network_scanner import scan_network
from scanners.web_scanner import scan_web

def main():
    parser = argparse.ArgumentParser(description="Caelis Scan - Python Vulnerability Scanner")
    parser.add_argument("--target", help="Target IP or URL to scan")
    parser.add_argument("--max-pages", type=int, default=25, help="Max pages to crawl (web targets only)")
    parser.add_argument("--no-crawl", action="store_true", help="Skip crawling, only scan the given URL")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE lookups against detected software")
    args = parser.parse_args()

    all_findings = []
    print("Starting Caelis Scan...\n")

    print("[*] Scanning local machine...")
    all_findings.extend(scan_local())

    if args.target:
        print(f"[*] Scanning target: {args.target}...")
        if args.target.startswith("http"):
            all_findings.extend(scan_web(
                args.target,
                max_pages=args.max_pages,
                do_crawl=not args.no_crawl,
                do_cve=not args.no_cve
            ))
        else:
            all_findings.extend(scan_network(args.target))

    print("\n Done Scan Complete. Results:\n")
    display_results(all_findings)

if __name__ == "__main__":
    main()
