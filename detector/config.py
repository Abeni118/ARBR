"""
Configuration for the Wazuh detection service.
Reads from environment variables (matches the project's .env.example pattern).
"""
import os

# Wazuh manager API
WAZUH_API_URL = os.getenv("WAZUH_API_URL", "https://localhost:55000")
WAZUH_API_USER = os.getenv("WAZUH_API_USER", "wazuh-wui")
WAZUH_API_PASSWORD = os.getenv("WAZUH_API_PASSWORD", "")
WAZUH_VERIFY_SSL = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

# Where to read raw alerts from when not using the API directly.
# Useful for local testing / tailing the manager's own alert log.
ALERTS_JSON_PATH = os.getenv("ALERTS_JSON_PATH", "/var/ossec/logs/alerts/alerts.json")

# Shared DB (matches project .env.example) - where normalized detections
# get written for Member 2's Risk Engine to consume.
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "attack_resistant_db")

# Detection tuning
MASS_CHANGE_THRESHOLD = int(os.getenv("MASS_CHANGE_THRESHOLD", "15"))   # files
MASS_CHANGE_WINDOW_SECONDS = int(os.getenv("MASS_CHANGE_WINDOW_SECONDS", "20"))
ENTROPY_SUSPICIOUS_THRESHOLD = float(os.getenv("ENTROPY_SUSPICIOUS_THRESHOLD", "7.5"))  # bits/byte, max 8

SUSPICIOUS_EXTENSIONS = {
    ".locked", ".encrypted", ".crypt", ".enc", ".ransom",
    ".wcry", ".wncry", ".locky", ".cerber", ".zzz", ".micro",
}

RANSOM_NOTE_PATTERNS = (
    "readme", "decrypt", "how_to", "restore_files", "ransom",
)
