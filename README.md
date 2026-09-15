# Caelis Scan

A modular security scanner designed to identify vulnerabilities across local systems, servers, and web applications.

## LEGAL DISCLAIMER
**This tool is for educational purposes and authorized security testing ONLY.** 
Scanning targets you do not own or have explicit written permission to test is illegal. The developer assumes no liability for misuse of this tool. Use it responsibly and ethically.

## Features
- **Local Auditor:** Checks system configurations and permissions.
- **Network Scanner:** Identifies open ports and services.
- **Web Scanner:** Analyzes HTTP headers for security flaws.
- **Risk-Based Reporting:** Color-coded results based on severity:
  - 🔴 **Very Risky** (Red)
  - 🟣 **Risky** (Pink/Magenta)
  - 🟡 **Medium** (Yellow)
  - 🔵 **Low** (Light Blue)
  - 🟢 **Info** (green)
# should I change info to no p
## Installation
1. Clone the repo:
   ```bash
   git clone https://github.com/aviator899/Caelis-scan.git
   cd Caelis-scan
   ```
2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
   if it didn't install use a virtual enviroment
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   ```
   
## Usage
**Local scan only:**
```bash
python main.py
```

**Scan a specific target:**
```bash
python main.py --target http://example.com
# OR
python main.py --target 192.168.1.1
# limit how many pages the crawler visits (default: 25)
python main.py --target http://example.com --max-pages 10
# scan only the given URL, skip crawling other pages
python main.py --target http://example.com --no-crawl
# skip CVE lookups against detected software versions
python main.py --target http://example.com --no-cve
```
