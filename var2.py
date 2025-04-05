import socket
import ssl
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
import shutil
import json
import argparse
import os
from datetime import datetime
from urllib.parse import urlparse
import requests
import random
import time
import logging
from typing import List, Dict, Optional, Union
from tqdm import tqdm
from pathlib import Path
import hashlib
from dataclasses import dataclass

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scanner.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Configuration
DEFAULT_PORTS = "1-1024"
DEFAULT_THREADS = 100
DEFAULT_TIMEOUT = 2
SCAN_DELAY = 0.1
CACHE_EXPIRY_DAYS = 7
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

@dataclass
class ScanResult:
    target: str
    timestamp: str
    open_ports: List[Dict]
    ssl_info: Optional[Dict]
    cms_info: Optional[str]
    nmap_info: Optional[str]
    vulnerabilities: List[Dict]
    subdomains: List[str]
    web_vulnerabilities: List[Dict]

class CVEChecker:
    def __init__(self, cache_dir: str = ".cve_cache"):
        self.cache_dir = cache_dir
        os.makedirs(self.cache_dir, exist_ok=True)
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": random.choice(USER_AGENTS),
            "Accept": "application/json"
        })

    def _get_cache_path(self, key: str) -> Path:
        """Generate cache file path from key"""
        hash_key = hashlib.md5(key.encode()).hexdigest()
        return Path(self.cache_dir) / f"{hash_key}.json"

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache is still valid"""
        if not cache_path.exists():
            return False
        cache_age = time.time() - cache_path.stat().st_mtime
        return cache_age < (CACHE_EXPIRY_DAYS * 86400)

    def _query_cve_api(self, product: str) -> Optional[Dict]:
        """Query CVE API for a product"""
        try:
            # Using CVE Search API (replace with actual API endpoint)
            url = f"https://cve.circl.lu/api/search/{product}"
            response = self.session.get(url, timeout=10)
            response.raise_for_status()
            return response.json()
        except Exception as e:
            logger.warning(f"Failed to query CVE API for {product}: {str(e)}")
            return None

    def get_cves(self, product: str) -> List[Dict]:
        """Get CVEs for a product with caching"""
        cache_path = self._get_cache_path(product)
        
        # Try to load from cache
        if self._is_cache_valid(cache_path):
            try:
                with open(cache_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                logger.warning(f"Failed to load cache for {product}: {str(e)}")

        # Query API if cache is invalid
        result = self._query_cve_api(product)
        if result is None:
            return []

        # Save to cache
        try:
            with open(cache_path, 'w') as f:
                json.dump(result, f)
        except Exception as e:
            logger.warning(f"Failed to save cache for {product}: {str(e)}")

        return result

class Scanner:
    def __init__(self, verbose: bool = False, timeout: int = DEFAULT_TIMEOUT):
        self.verbose = verbose
        self.timeout = timeout
        self.cve_checker = CVEChecker()
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        
        if verbose:
            logger.setLevel(logging.DEBUG)

    def parse_port_range(self, port_spec: str) -> List[int]:
        """Parse port range specification into list of ports"""
        ports = []
        for part in port_spec.split(','):
            if '-' in part:
                start, end = map(int, part.split('-'))
                ports.extend(range(start, end + 1))
            else:
                ports.append(int(part))
        return sorted(set(ports))

    def grab_banner(self, ip: str, port: int) -> Optional[str]:
        """Attempt to grab banner from open port"""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout) as s:
                s.settimeout(self.timeout)
                
                # Protocol-specific probes
                if port == 80 or port == 443:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                elif port == 21:
                    s.sendall(b"USER anonymous\r\n")
                elif port == 22:
                    s.sendall(b"SSH-2.0-Client\r\n")
                elif port == 25:
                    s.sendall(b"EHLO example.com\r\n")
                
                banner = s.recv(1024).decode(errors="ignore")
                return banner.strip()
        except Exception as e:
            logger.debug(f"Banner grab failed for {ip}:{port}: {str(e)}")
            return None

    def scan_tcp_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan a single TCP port"""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                banner = self.grab_banner(ip, port)
                logger.info(f"TCP Port {port} is open on {ip}")
                return {"port": port, "protocol": "tcp", "banner": banner}
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"TCP scan failed for {ip}:{port}: {str(e)}")
            return None

    def scan_udp_port(self, ip: str, port: int) -> Optional[Dict]:
        """Scan a single UDP port"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                sock.settimeout(self.timeout)
                sock.sendto(b"\x00", (ip, port))
                data, _ = sock.recvfrom(1024)
                logger.info(f"UDP Port {port} is open on {ip}")
                return {"port": port, "protocol": "udp", "banner": data.decode(errors="ignore")}
        except socket.timeout:
            return None
        except Exception as e:
            logger.debug(f"UDP scan failed for {ip}:{port}: {str(e)}")
            return None

    def scan_ports(self, ip: str, ports: List[int], max_threads: int = DEFAULT_THREADS) -> List[Dict]:
        """Scan multiple ports using threading with progress bar"""
        open_ports = []
        
        logger.info(f"Scanning {len(ports)} ports on {ip}")
        
        # TCP scan with progress bar
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_tcp_port, ip, port): port for port in ports}
            for future in tqdm(as_completed(futures), total=len(futures), desc="TCP Scan"):
                result = future.result()
                if result:
                    open_ports.append(result)
                time.sleep(SCAN_DELAY)

        # UDP scan with progress bar
        with ThreadPoolExecutor(max_workers=max_threads) as executor:
            futures = {executor.submit(self.scan_udp_port, ip, port): port for port in ports}
            for future in tqdm(as_completed(futures), total=len(futures), desc="UDP Scan"):
                result = future.result()
                if result:
                    open_ports.append(result)
                time.sleep(SCAN_DELAY)

        return open_ports

    def check_ssl(self, ip: str, port: int = 443) -> Optional[Dict]:
        """Check SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        "subject": dict(x[0] for x in cert.get("subject", ())),
                        "issuer": dict(x[0] for x in cert.get("issuer", ())),
                        "valid_from": cert.get("notBefore"),
                        "valid_until": cert.get("notAfter"),
                        "version": cert.get("version"),
                        "serial_number": cert.get("serialNumber"),
                    }
        except Exception as e:
            logger.warning(f"SSL check failed for {ip}:{port}: {str(e)}")
            return None

    def detect_cms(self, ip: str) -> Optional[str]:
        """Detect CMS using whatweb"""
        if not shutil.which("whatweb"):
            logger.warning("whatweb not installed - skipping CMS detection")
            return None
        
        try:
            output = subprocess.check_output(
                ["whatweb", "-a", "3", "--color=never", ip],
                stderr=subprocess.DEVNULL,
                timeout=30
            ).decode()
            return output.strip()
        except subprocess.TimeoutExpired:
            logger.warning("CMS detection timed out")
            return None
        except Exception as e:
            logger.warning(f"CMS detection failed: {str(e)}")
            return None

    def nmap_scan(self, ip: str, ports: List[int]) -> Optional[str]:
        """Perform nmap service detection scan"""
        if not shutil.which("nmap"):
            logger.warning("nmap not installed - skipping nmap scan")
            return None
        
        try:
            port_str = ",".join(map(str, ports))
            output = subprocess.check_output(
                ["nmap", "-sV", "-T4", "-p", port_str, ip],
                stderr=subprocess.DEVNULL,
                timeout=300  # 5 minute timeout
            ).decode()
            return output.strip()
        except subprocess.TimeoutExpired:
            logger.warning("nmap scan timed out")
            return None
        except Exception as e:
            logger.warning(f"nmap scan failed: {str(e)}")
            return None

    def match_vulnerabilities(self, banners: List[Dict]) -> List[Dict]:
        """Match banners against known vulnerabilities using CVE database"""
        vulns = []
        
        for item in banners:
            if not item.get("banner"):
                continue
            
            banner = item["banner"]
            
            # Extract potential product names
            products = []
            if "Apache" in banner:
                products.append("Apache")
                version = banner.split("Apache/")[1].split()[0].split(".")[0]
                products.append(f"Apache_{version}")
            elif "nginx" in banner:
                products.append("nginx")
                version = banner.split("nginx/")[1].split()[0].split(".")[0]
                products.append(f"nginx_{version}")
            elif "OpenSSH" in banner:
                products.append("OpenSSH")
                version = banner.split("OpenSSH_")[1].split()[0].replace(".", "")
                products.append(f"OpenSSH_{version}")
            elif "MySQL" in banner:
                products.append("MySQL")
                version = banner.split("MySQL ")[1].split()[0].split(".")[0]
                products.append(f"MySQL_{version}")
            
            # Query CVE database for each product
            for product in products:
                cves = self.cve_checker.get_cves(product)
                if cves:
                    for cve in cves:
                        vulns.append({
                            "port": item["port"],
                            "protocol": item["protocol"],
                            "cve": cve.get("id", "Unknown"),
                            "product": product,
                            "banner": banner,
                            "confidence": "medium",
                            "description": cve.get("summary", "No description available")
                        })
        
        return vulns

    def enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate common subdomains with progress bar"""
        subdomains = []
        wordlist = ["www", "mail", "ftp", "dev", "test", "admin", "webmail",
                   "secure", "api", "app", "beta", "staging", "m", "mobile",
                   "blog", "shop", "store", "support", "status"]
        
        logger.info(f"Enumerating subdomains for {domain}")
        
        for sub in tqdm(wordlist, desc="Subdomain Enumeration"):
            url = f"http://{sub}.{domain}"
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code < 400:
                    subdomains.append(f"{sub}.{domain}")
                    logger.debug(f"Found subdomain: {sub}.{domain}")
            except Exception as e:
                logger.debug(f"Subdomain check failed for {url}: {str(e)}")
                continue
        
        return subdomains

    def scan_web_vulnerabilities(self, target_url: str) -> List[Dict]:
        """Check for web vulnerabilities with progress tracking"""
        if not target_url.startswith(('http://', 'https://')):
            target_url = f"http://{target_url}"
            
        logger.info(f"Testing {target_url} for web vulnerabilities")
        
        payloads = [
            ("<script>alert(1)</script>", "xss"),
            ("' OR '1'='1", "sqli"),
            ("\" OR \"1\"=\"1", "sqli"),
            ("1 AND 1=1", "sqli"),
            ("1 AND 1=2", "sqli"),
            ("<img src=x onerror=alert(1)>", "xss"),
            ("${7*7}", "ssti"),
            ("../../../../etc/passwd", "lfi"),
            (";cat /etc/passwd", "command_injection")
        ]
        findings = []
        
        for payload, vuln_type in tqdm(payloads, desc="Web Vulnerability Scan"):
            try:
                # Test in URL parameters
                r = self.session.get(target_url, params={"q": payload}, timeout=self.timeout)
                if payload in r.text:
                    findings.append({
                        "type": vuln_type,
                        "location": "URL parameter",
                        "payload": payload,
                        "confidence": "medium",
                        "url": r.url
                    })
                
                # Test in POST data if it's a form
                if r.text.lower().count("<form") > 0:
                    try:
                        form_data = {f"field{i}": payload for i in range(1, 4)}
                        r_post = self.session.post(target_url, data=form_data, timeout=self.timeout)
                        if payload in r_post.text:
                            findings.append({
                                "type": vuln_type,
                                "location": "POST data",
                                "payload": payload,
                                "confidence": "medium",
                                "url": target_url
                            })
                    except:
                        pass
                        
            except Exception as e:
                logger.debug(f"Web vulnerability check failed for {payload}: {str(e)}")
                continue
        
        return findings

    def save_results(self, result: ScanResult, filename: str):
        """Save scan results to JSON file"""
        os.makedirs(os.path.dirname(filename), exist_ok=True)
        try:
            with open(filename, "w") as f:
                json.dump(result.__dict__, f, indent=4)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Failed to save results: {str(e)}")

    def scan_target(self, ip: str, ports: List[int], threads: int, outdir: str) -> ScanResult:
        """Complete scan of a single target"""
        result = ScanResult(
            target=ip,
            timestamp=str(datetime.now()),
            open_ports=[],
            ssl_info=None,
            cms_info=None,
            nmap_info=None,
            vulnerabilities=[],
            subdomains=[],
            web_vulnerabilities=[]
        )
        
        # Port scanning
        result.open_ports = self.scan_ports(ip, ports, threads)
        
        # SSL check (if HTTPS port is open)
        if any(p["port"] == 443 for p in result.open_ports):
            result.ssl_info = self.check_ssl(ip)
        
        # CMS detection (if HTTP port is open)
        if any(p["port"] in [80, 443, 8080, 8443] for p in result.open_ports):
            result.cms_info = self.detect_cms(ip)
        
        # Nmap scan if available
        result.nmap_info = self.nmap_scan(ip, ports)
        
        # Vulnerability matching
        result.vulnerabilities = self.match_vulnerabilities(result.open_ports)
        
        # Subdomain enumeration (for domains)
        if not ip.replace(".", "").isdigit():  # If it's not just an IP address
            result.subdomains = self.enumerate_subdomains(ip)
        
        # Web vulnerability testing
        if any(p["port"] in [80, 443, 8080, 8443] for p in result.open_ports):
            result.web_vulnerabilities = self.scan_web_vulnerabilities(ip)
        
        # Save results
        cleaned_ip = ip.replace("http://", "").replace("https://", "").replace(":", "_").replace("/", "_").replace(".", "_")
        self.save_results(result, f"{outdir}/{cleaned_ip}_scan.json")
        
        return result

def main():
    print("""
    #############################################
    #          ADVANCED SECURITY SCANNER        #
    #  Use only on systems you have permission  #
    #        to scan. Unauthorized scanning     #
    #        may be illegal in your region.     #
    #############################################
    """)

    parser = argparse.ArgumentParser(description="Advanced Security Scanner")
    parser.add_argument("-u", "--url", help="Single target IP or domain")
    parser.add_argument("-l", "--list", help="File with list of targets")
    parser.add_argument("-o", "--output", default="results", help="Directory to store output")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, 
                        help=f"Number of threads (default: {DEFAULT_THREADS})")
    parser.add_argument("-p", "--ports", default=DEFAULT_PORTS, 
                        help=f"Ports to scan (e.g., '80,443,8000-9000') (default: {DEFAULT_PORTS})")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help=f"Connection timeout in seconds (default: {DEFAULT_TIMEOUT})")

    args = parser.parse_args()

    scanner = Scanner(verbose=args.verbose, timeout=args.timeout)
    
    targets = []
    if args.url:
        parsed = urlparse(args.url if "://" in args.url else f"http://{args.url}")
        host = parsed.hostname
        targets.append(host)
    if args.list:
        try:
            with open(args.list, "r") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        parsed = urlparse(line if "://" in line else f"http://{line}")
                        host = parsed.hostname
                        targets.append(host)
        except FileNotFoundError:
            logger.error(f"Target list file not found: {args.list}")
            return

    if not targets:
        logger.error("No targets specified")
        return

    try:
        ports = scanner.parse_port_range(args.ports)
    except ValueError as e:
        logger.error(f"Invalid port specification: {str(e)}")
        return

    logger.info(f"Starting scan with {args.threads} threads on ports: {args.ports}")

    for ip in targets:
        logger.info(f"\nStarting scan for: {ip}")
        try:
            scanner.scan_target(ip, ports, args.threads, args.output)
        except Exception as e:
            logger.error(f"Scan failed for {ip}: {str(e)}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        exit(1)