"""
utils.py
Utility helpers for validation, formatting, timestamps, and messaging.
Used across the scanner modules.
"""

import ipaddress
from datetime import datetime

def is_valid_ip(target: str) -> bool:
    # Return True if input is a valid IP address
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def is_probably_domain(target: str) -> bool:
    # Basic domain check (not strict)
    return "." in target and " " not in target


def normalize_target(target: str) -> str:
    # Trim whitespace from target input.
    return target.strip()


def print_error(msg: str) -> None:
    # Formatted error output.
    print(f"[ERROR] {msg}")


def print_info(msg: str) -> None:
    # Formatted informational output
    print(f"[INFO] {msg}")


def now_iso() -> str:
    # Return UTC timestamp in ISO-like format for filenames.
    return datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
