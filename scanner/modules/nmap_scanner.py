"""
nmap_scanner.py
Handles all Nmap-based network scanning and returns structured results.
"""

import nmap
from typing import Dict, Any, List
from ..config import SCAN_PROFILES
from ..utils import print_info, print_error


def run_nmap_scan(target: str, profile_name: str = "network-basic") -> Dict[str, Any]:
    """
    Run an Nmap scan based on the selected profile.
    Returns a dict containing port/service information.
    """

    profile = SCAN_PROFILES.get(profile_name)
    if not profile:
        raise ValueError(f"Unknown scan profile: {profile_name}")

    nmap_args = profile["nmap_args"]
    scanner = nmap.PortScanner()

    print_info(f"Running Nmap scan on {target} with args: {nmap_args}")

    try:
        scanner.scan(target, arguments=nmap_args)
    except Exception as e:
        print_error(f"Nmap scan failed: {e}")
        return {"target": target, "ports": []}

    ports_info: List[Dict[str, Any]] = []

    # Extract ports and metadata from Nmap results
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            for port, port_data in scanner[host][proto].items():
                ports_info.append(
                    {
                        "port": port,
                        "protocol": proto,
                        "state": port_data.get("state", ""),
                        "service": port_data.get("name", ""),
                        "product": port_data.get("product", ""),
                        "version": port_data.get("version", ""),
                    }
                )

    return {
        "target": target,
        "ports": ports_info,
    }
