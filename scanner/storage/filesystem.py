"""
filesystem.py
Handles saving scan results to JSON files on disk.
"""

import json
from pathlib import Path
from typing import Dict, Any, Optional
from ..config import RESULTS_DIR
from ..utils import now_iso


def save_scan_result(target: str, profile_name: str, data: Dict[str, Any]) -> Path:
    """
    Save a single scan result (analysis output) to a JSON file.
    Returns the full path to the saved file.
    """

    timestamp = now_iso()
    # Example filename: 20251208T193000Z_scanme.nmap.org_network-basic.json
    filename = f"{timestamp}_{target}_{profile_name}.json"
    safe_filename = filename.replace(":", "").replace("/", "_").replace("\\", "_")

    path = RESULTS_DIR / safe_filename

    payload = {
        "target": target,
        "profile": profile_name,
        "timestamp": timestamp,
        "data": data,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)

    return path


def _safe_read_json(path: Path) -> Optional[Dict[str, Any]]:
    """Read one JSON file safely and return None on parse/read errors."""

    try:
        with open(path, "r", encoding="utf-8") as file_obj:
            parsed = json.load(file_obj)
            if isinstance(parsed, dict):
                return parsed
    except Exception:
        return None

    return None


def load_scan_result_from_path(file_path: str) -> Optional[Dict[str, Any]]:
    """Load one saved scan result by absolute/relative file path."""

    path = Path(file_path)
    candidates = [path]

    # Convenience fallback: allow passing only the filename from results/.
    if not path.is_absolute():
        candidates.append(RESULTS_DIR / path)

    for candidate in candidates:
        if candidate.exists() and candidate.is_file():
            return _safe_read_json(candidate)

    return None


def load_latest_scan_result(target: str, profile_name: str) -> Optional[Dict[str, Any]]:
    """Load the latest saved scan result for the same target/profile."""

    pattern = f"*_{target}_{profile_name}.json"
    candidates = sorted(RESULTS_DIR.glob(pattern), reverse=True)

    for path in candidates:
        parsed = _safe_read_json(path)
        if parsed:
            return parsed

    return None
