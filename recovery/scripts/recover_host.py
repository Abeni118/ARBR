import os
import subprocess
import logging
import platform

# Configure logging for recovery events
logging.basicConfig(
    filename='recovery.log',
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def restore_system():
    """
    Detects the operating system and resets firewall rules 
    to restore full network connectivity after an incident is resolved.
    """
    current_os = platform.system()
    logging.info(f"INFO: Recovery protocol triggered on {current_os}.")
    print(f"[*] INFO: Recovery protocol initiated on {current_os}...")

    try:
        if current_os == "Windows":
            print("[*] Resetting Windows Firewall policies to default...")
            # Reset firewall to default state (allowing traffic again)
            subprocess.run(["netsh", "advfirewall", "reset"], check=True, capture_output=True)
            # Restore default firewall policy (allow outbound, block inbound by default)
            subprocess.run(["netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,allowoutbound"], check=True, capture_output=True)
            
        elif current_os == "Linux":
            print("[*] Flushing iptables rules and restoring default policies...")
            # Flush existing rules and reset policies back to ACCEPT (requires root/sudo)
            subprocess.run(["sudo", "iptables", "-F"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "INPUT", "ACCEPT"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"], check=True)
            subprocess.run(["sudo", "iptables", "-P", "FORWARD", "ACCEPT"], check=True)
            
        else:
            raise Exception(f"Unsupported operating system: {current_os}")

        logging.info(f"System successfully restored to normal state on {current_os}.")
        print(f"[+] System successfully restored on {current_os}.")
        
    except Exception as e:
        logging.error(f"Failed to restore system: {e}")
        print(f"[-] Error during recovery: {e}")

if __name__ == "__main__":
    restore_system()