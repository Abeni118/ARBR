import os
import subprocess
import logging
import platform

logging.basicConfig(
    filename='isolation.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def isolate_system():
   
    current_os = platform.system()
    logging.warning(f"CRITICAL: Isolation protocol triggered on {current_os}!")
    print(f"[!] CRITICAL: Isolation protocol initiated on {current_os}...")

    try:
        if current_os == "Windows":
            print("[*] Applying Windows Firewall lockdown...")
            subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "state", "on"], check=True, capture_output=True)
            subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"], check=True, capture_output=True)
            
        elif current_os == "Linux":
            print("[*] Applying Linux iptables lockdown...")
            subprocess.run(["sudo", "iptables", "-P", "INPUT", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "DROP"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "INPUT", "-i", "lo", "-j", "ACCEPT"], check=True)
            subprocess.run(["sudo", "iptables", "-A", "OUTPUT", "-o", "lo", "-j", "ACCEPT"], check=True)
            
        else:
            raise Exception(f"Unsupported operating system: {current_os}")

        logging.info(f"System successfully isolated on {current_os}.")
        print(f"[+] System successfully isolated on {current_os}.")
        
    except Exception as e:
        logging.error(f"Failed to isolate system: {e}")
        print(f"[-] Error during isolation: {e}")

if __name__ == "__main__":
    isolate_system()