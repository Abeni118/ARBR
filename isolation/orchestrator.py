import sys
import os
import argparse

current_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.abspath(os.path.join(current_dir, ".."))
sys.path.append(os.path.join(current_dir, "scripts"))
sys.path.append(os.path.join(project_root, "recovery", "scripts"))

try:
    from isolate_host import isolate_system
    from recover_host import restore_system
except ImportError:
    from scripts.isolate_host import isolate_system
    from recovery.scripts.recover_host import restore_system

def main():
    parser = argparse.ArgumentParser(description="System Isolation & Recovery Control Panel")
    parser.add_argument(
        "--action", 
        required=True, 
        choices=["isolate", "recover"], 
        help="Specify whether to isolate the host or recover/restore it."
    )
    
    args = parser.parse_args()

    print(f"[*] Member 5 Orchestrator received command: {args.action.upper()}")

    if args.action == "isolate":
        print("[!] Executing system isolation protocol...")
        isolate_system()
    elif args.action == "recover":
        print("[*] Executing system recovery and restoration protocol...")
        restore_system()

if __name__ == "__main__":
    main()