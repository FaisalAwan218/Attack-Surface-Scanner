"""
config.py
Central configuration for the Attack Surface Scanner.
Includes scan profiles, risk mappings, and paths for saving results.
"""

from pathlib import Path

# Base directory (project root)
BASE_DIR = Path(__file__).resolve().parent.parent

# Folder where scan results are stored
RESULTS_DIR = BASE_DIR / "results"
RESULTS_DIR.mkdir(exist_ok=True)

# Default Nmap arguments
DEFAULT_NMAP_ARGS = "-sV -T4"

# Port-to-risk level mapping for basic risk assessment
RISK_PORT_MAPPING = {
    21: "HIGH",
    22: "MEDIUM",
    23: "HIGH",
    25: "MEDIUM",
    53: "MEDIUM",
    80: "LOW",
    110: "MEDIUM",
    143: "MEDIUM",
    443: "LOW",
    445: "HIGH",
    3389: "HIGH",
    5900: "MEDIUM"
}

# Scan profiles (used by CLI to control modules and aggressiveness)
SCAN_PROFILES = {
    "network-basic": {
        "nmap_args": DEFAULT_NMAP_ARGS,
        "run_web": False,
    },
    "web-focused": {
        "nmap_args": "-sV -T4 -p 80,443,8080,8443",
        "run_web": True,
    },
}
