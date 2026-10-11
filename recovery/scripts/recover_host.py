import logging
import subprocess


logging.basicConfig(
    filename="recovery.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)


TABLE = "arbr_isolation"


def run_nft(command: str) -> None:
    subprocess.run(
        ["sudo", "-n", "nft", *command.split()],
        check=True,
        capture_output=True,
        text=True,
    )


def restore_project_firewall() -> bool:
    """Restore the project's nftables isolation rules."""

    try:
        logging.info("Starting project firewall recovery.")

        run_nft(f"flush chain inet {TABLE} input")
        run_nft(f"flush chain inet {TABLE} output")

        run_nft(
            f"add rule inet {TABLE} input "
            "iifname lo accept"
        )

        run_nft(
            f"add rule inet {TABLE} input "
            "ct state established,related accept"
        )

        run_nft(
            f"add rule inet {TABLE} input "
            "ip saddr 192.168.56.1 tcp dport 22 accept"
        )

        run_nft(
            f"add rule inet {TABLE} output "
            "oifname lo accept"
        )

        run_nft(
            f"add rule inet {TABLE} output "
            "ct state established,related accept"
        )

        logging.info("Project firewall successfully restored.")
        return True

    except subprocess.CalledProcessError as error:
        logging.error(
            "Project firewall recovery failed: %s",
            error,
        )
        return False


if __name__ == "__main__":
    if restore_project_firewall():
        print("[+] Project firewall restored successfully.")
    else:
        print("[-] Project firewall recovery failed.")