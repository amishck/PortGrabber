# 🚀PortGrabber

PortGrabber comprehensive security scanning tool for network reconnaissance and vulnerability assessment.Equipped with multi-threading and modular scanning options.

## 🔍Features

🔓 TCP & UDP Port Scanning
🎯 Banner Grabbing
🔐 SSL Certificate Analysis
🕵️ CMS Detection using WhatWeb
📡 Service enumeration with nmap
🛡️ CVE Vulnerability Matching
🌐 Subdomain Enumeration
🧪 Web Vulnerability Testing – Basic detection for XSS, SQLi, and other common attacks
⚡ Multi-threading Support
📄 Structured JSON Reports
📈 Progress Tracking & Logging

## ⚙️Installation

```bash
# Clone the repository
git clone https://github.com/amishck/PortGrabber.git
cd PortGrabber

# Install dependencies
pip install -r requirements.txt

# Install optional tools for enhanced functionality
# On Debian/Ubuntu:
sudo apt-get install nmap whatweb
```

## 🧾Requirements

- Python 3.7+
- Required Python packages (see requirements.txt):
  - requests
  - colorama
  - tqdm
  - typing
- Optional tools:
  - nmap - Advanced network scanning
  - whatweb - CMS and tech fingerprinting

## 🚦Usage

```bash
python var2.py -u example.com
python var2.py -l targets.txt -v
python PortGrabber.py -u example.com -o result
python var2.py -u example.com -p "80,443,8000-9000" -t 50 --timeout 3
```

## 🛠️Arguments

```
-u, --url           Single target IP or domain
-l, --list          File with list of targets
-o, --output        Directory to store output (default: "results")
-t, --threads       Number of threads (default: 100)
-p, --ports         Ports to scan in format like '80,443,8000-9000' (default: "1-1024")
-v, --verbose       Verbose output
--timeout           Connection timeout in seconds (default: 2)
```

## 📁Output

Results are saved in JSON format in the specified output directory (default: "results/"). The output includes:

- Open ports (TCP/UDP)
- Service banners
- SSL certificate information
- Detected CMS details
- Service information from nmap (if available)
- Potential vulnerabilities
- Discovered subdomains
- Web vulnerability findings

## ⚠️Disclaimer

This tool is intended for educational purposes and authorized penetration testing only. Do not scan networks or systems you do not own or have explicit permission to test. Unauthorized use may be illegal and is strictly discouraged. Always obtain permission before scanning any systems you don't own.

## 📜License

[MIT License](LICENSE)
