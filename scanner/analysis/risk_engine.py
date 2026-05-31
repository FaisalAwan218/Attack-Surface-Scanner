"""
risk_engine.py
Takes raw scan results and assigns basic risk levels and summary stats.
"""

from typing import Dict, Any, List
from ..config import RISK_PORT_MAPPING


def _calculate_attack_surface_score(risk_counts: Dict[str, int], total_ports: int) -> Dict[str, Any]:
    """Compute a simple normalized score and severity label."""

    weighted = (
        risk_counts.get("HIGH", 0) * 10
        + risk_counts.get("MEDIUM", 0) * 6
        + risk_counts.get("LOW", 0) * 2
        + risk_counts.get("UNKNOWN", 0) * 4
        + total_ports
    )

    score = min(100, weighted)
    if score >= 70:
        level = "HIGH"
    elif score >= 40:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "value": score,
        "level": level,
        "method": "weighted-port-risk",
    }


def analyze_scan_results(scan_results: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enrich scan results with risk levels and basic summary.
    Expects scan_results in the format returned by nmap_scanner.run_nmap_scan().
    """

    ports = scan_results.get("ports", [])
    analyzed_ports: List[Dict[str, Any]] = []

    risk_counts = {
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
        "UNKNOWN": 0,
    }

    for p in ports:
        port_num = p.get("port")
        risk = RISK_PORT_MAPPING.get(port_num, "UNKNOWN")

        enriched = {
            **p,
            "risk": risk,
        }
        analyzed_ports.append(enriched)
        risk_counts[risk] = risk_counts.get(risk, 0) + 1

    summary = {
        "total_ports": len(ports),
        "risk_counts": risk_counts,
        "attack_surface_score": _calculate_attack_surface_score(risk_counts, len(ports)),
    }

    return {
        "ports": analyzed_ports,
        "summary": summary,
    }
