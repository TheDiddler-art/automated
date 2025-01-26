from colorama import init, Fore
import os
import sys

def install_termux_requirements():
    print(f"\n{Fore.BLUE}[*] Installing Termux Requirements{Fore.RESET}")
    
    pkg_commands = [
        "pkg update -y",
        "pkg upgrade -y",
        "pkg install -y root-repo",
        "pkg install -y python",
        "pkg install -y nmap",
        "pkg install -y python-dev",
        "pkg install -y wireless-tools",
        "pkg install -y hydra",
        "pkg install -y gobuster",
        "pkg install -y aircrack-ng",
        "pkg install -y tcpdump",
        "pkg install -y macchanger",
        "pkg install -y mdk3",
        "pkg install -y dnsmasq",
        "pkg install -y libbluetooth",
        "pkg install -y bluetooth"
    ]
    
    pip_commands = [
        "pip install --upgrade pip",
        "pip install python-nmap",
        "pip install colorama",
        "pip install requests",
        "pip install scapy",
        "pip install pybluez",
        "pip install dnspython",
        "pip install paramiko",
        "pip install cryptography"
    ]
    
    try:
        for cmd in pkg_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            if os.system(cmd) != 0:
                print(f"{Fore.RED}[-] Failed: {cmd}{Fore.RESET}")
                return
            
        for cmd in pip_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            if os.system(cmd) != 0:
                print(f"{Fore.RED}[-] Failed: {cmd}{Fore.RESET}")
                return
                
        print(f"{Fore.GREEN}[+] Termux requirements installed!{Fore.RESET}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")

def install_windows_requirements():
    print(f"\n{Fore.BLUE}[*] Installing Windows Requirements{Fore.RESET}")
    
    print(f"{Fore.YELLOW}[!] Some tools need manual installation on Windows:")
    print("1. Nmap: https://nmap.org/download.html")
    print("2. Wireshark: https://www.wireshark.org/download.html")
    print(f"3. Other tools may have limited functionality on Windows{Fore.RESET}\n")
    
    pip_commands = [
        "pip install --upgrade pip",
        "pip install python-nmap",
        "pip install colorama",
        "pip install requests",
        "pip install scapy",
        "pip install paramiko",
        "pip install cryptography",
        "pip install dnspython"
    ]
    
    try:
        for cmd in pip_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            if os.system(cmd) != 0:
                print(f"{Fore.RED}[-] Failed: {cmd}{Fore.RESET}")
                return
                
        print(f"{Fore.GREEN}[+] Windows requirements installed!")
        print(f"[*] Note: Some features require additional setup{Fore.RESET}")
        
    except Exception as e:
        print(f"{Fore.RED}[-] Error: {str(e)}{Fore.RESET}")

def main():
    init()  # Initialize colorama
    
    while True:
        print(f"\n{Fore.GREEN}=== Install Requirements ==={Fore.RESET}")
        print(f"{Fore.YELLOW}[1] Windows Requirements")
        print(f"[2] Termux Requirements")
        print(f"[3] Exit{Fore.RESET}")
        
        choice = input(f"\n{Fore.CYAN}Select option: {Fore.RESET}")
        
        if choice == "1":
            install_windows_requirements()
        elif choice == "2":
            install_termux_requirements()
        elif choice == "3":
            break
        else:
            print(f"{Fore.RED}[-] Invalid option{Fore.RESET}")

if __name__ == "__main__":
    main() 