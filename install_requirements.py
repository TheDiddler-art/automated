from colorama import init, Fore
import os
import sys

def install_termux_requirements():
    print(f"\n{Fore.BLUE}[*] Installing Termux Requirements{Fore.RESET}")
    
    # First add all required repositories
    repo_commands = [
        "pkg install -y root-repo",
        "pkg install -y unstable-repo",
        "pkg install -y x11-repo"
    ]
    
    pkg_commands = [
        # Core updates
        "pkg update -y",
        "pkg upgrade -y",
        
        # Python and dev tools
        "pkg install -y python",
        "pkg install -y python-static",
        "pkg install -y git",
        "pkg install -y python-pip",
        
        # Network tools
        "pkg install -y nmap",
        "pkg install -y wireless-tools",
        "pkg install -y tcpdump",
        "pkg install -y netcat-openbsd",
        "pkg install -y openssh",
        
        # Additional utils
        "pkg install -y tsu",
        "pkg install -y wget",
        "pkg install -y curl"
    ]
    
    pip_commands = [
        # Network modules
        "pip install python-nmap",
        "pip install scapy",
        "pip install requests",
        "pip install dnspython",
        
        # Utils
        "pip install colorama",
        "pip install python-dateutil",
        "pip install netifaces"
    ]
    
    try:
        # First install repositories
        print(f"{Fore.YELLOW}[+] Adding required repositories...{Fore.RESET}")
        for cmd in repo_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            os.system(cmd)
        
        # Update after adding repos
        print(f"{Fore.YELLOW}[+] Updating package lists...{Fore.RESET}")
        os.system("pkg update -y")
        
        # Install packages
        for cmd in pkg_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            if os.system(cmd) != 0:
                print(f"{Fore.RED}[-] Failed: {cmd}")
                print(f"[-] Continuing with other packages...{Fore.RESET}")
                continue
            
        # Install Python packages
        for cmd in pip_commands:
            print(f"{Fore.YELLOW}[+] Running: {cmd}{Fore.RESET}")
            if os.system(cmd) != 0:
                print(f"{Fore.RED}[-] Failed: {cmd}")
                print(f"[-] Continuing with other packages...{Fore.RESET}")
                continue
                
        print(f"\n{Fore.GREEN}[+] Basic requirements installed!")
        print(f"\n{Fore.YELLOW}[*] For additional tools, run these commands manually:")
        print(f"pkg install aircrack-ng")
        print(f"pkg install hydra")
        print(f"pkg install sqlmap")
        print(f"pkg install mdk3")
        print(f"pkg install hostapd")
        print(f"\n[*] For Bluetooth tools:")
        print(f"pkg install bluez")
        print(f"pkg install libbluetooth")
        print(f"pkg install bluetooth")
        print(f"\n[*] Then run:")
        print(f"termux-setup-storage{Fore.RESET}")
        
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
