# PortGrabber

A comprehensive security scanning tool for network reconnaissance and vulnerability assessment.

## Features

- TCP and UDP port scanning with banner grabbing
- SSL certificate analysis
- CMS detection using whatweb
- Service enumeration with nmap
- Vulnerability matching against CVE database
- Subdomain enumeration
- Web vulnerability testing (XSS, SQL Injection, etc.)
- Multi-threading for faster scanning
- Detailed JSON reports
- Progress tracking and logging

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/security-scanner.git
cd security-scanner

# Install dependencies
pip install -r requirements.txt

# Install optional tools for enhanced functionality
# On Debian/Ubuntu:
sudo apt-get install nmap whatweb
```

## Requirements

- Python 3.7+
- Required Python packages (see requirements.txt):
  - requests
  - colorama (for new.py)
  - tqdm (for var2.py)
  - typing (for var2.py)
- Optional tools:
  - nmap
  - whatweb

## Usage

### Basic Scanner (new.py)

```bash
python new.py -u example.com
python new.py -l targets.txt -v
python new.py -u example.com --start-port 1 --end-port 1000 -t 50
```

### Advanced Scanner (var2.py) - Recommended

```bash
python var2.py -u example.com
python var2.py -l targets.txt -v
python var2.py -u example.com -p "80,443,8000-9000" -t 50 --timeout 3
```

## Arguments

### new.py

```
-u, --url           Single target IP or domain
-l, --list          File with list of targets
-o, --output        Directory to store output (default: "results")
-t, --threads       Number of threads (default: 100)
--start-port        Start port for scanning range (default: 1)
--end-port          End port for scanning range (default: 1024)
-v, --verbose       Verbose output
```

### var2.py

```
-u, --url           Single target IP or domain
-l, --list          File with list of targets
-o, --output        Directory to store output (default: "results")
-t, --threads       Number of threads (default: 100)
-p, --ports         Ports to scan in format like '80,443,8000-9000' (default: "1-1024")
-v, --verbose       Verbose output
--timeout           Connection timeout in seconds (default: 2)
```

## Output

Results are saved in JSON format in the specified output directory (default: "results/"). The output includes:

- Open ports (TCP/UDP)
- Service banners
- SSL certificate information
- Detected CMS details
- Service information from nmap (if available)
- Potential vulnerabilities
- Discovered subdomains
- Web vulnerability findings

## Disclaimer

This tool is for educational purposes and authorized security testing only. Unauthorized scanning of networks may be illegal. Always obtain permission before scanning any systems you don't own.

## License

[MIT License](LICENSE)
