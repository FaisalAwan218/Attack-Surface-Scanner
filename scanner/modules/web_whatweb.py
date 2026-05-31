"""
web_whatweb.py
Runs WhatWeb for technology fingerprinting and returns structured web findings.
"""

import json
import os
import shutil
import subprocess
import tempfile
from urllib.parse import urlparse
from typing import Dict, Any, List


def _delete_temp_file(path: str) -> None:
	"""Delete a temporary file if it exists."""

	if os.path.exists(path):
		os.unlink(path)


def _build_candidate_urls(target: str) -> List[str]:
	"""Return one or two URLs to try with WhatWeb."""

	parsed = urlparse(target)
	if parsed.scheme and parsed.netloc:
		return [target]

	host = target.strip().strip("/")
	return [f"https://{host}", f"http://{host}"]


def _as_text_list(value: Any) -> List[str]:
	"""Normalize scalar/list values into a cleaned string list."""

	if isinstance(value, list):
		raw_items = value
	elif value is None:
		raw_items = []
	else:
		raw_items = [value]

	cleaned: List[str] = []
	for item in raw_items:
		text = str(item).strip()
		if text and text not in cleaned:
			cleaned.append(text)

	return cleaned


def _extract_plugin_values(plugin_details: Any) -> List[str]:
	"""Extract meaningful evidence values from one plugin block."""

	if not isinstance(plugin_details, dict):
		return []

	values: List[str] = []

	# Keep Country-like two-part values together, e.g. UNITED STATES [US].
	string_values = _as_text_list(plugin_details.get("string"))
	module_values = _as_text_list(plugin_details.get("module"))
	combined_used = False
	if string_values and module_values:
		combined_used = True
		for index, text in enumerate(string_values):
			module_part = module_values[index] if index < len(module_values) else ", ".join(module_values)
			combined = f"{text} [{module_part}]".strip()
			if combined and combined not in values:
				values.append(combined)

	for key in ("version", "string", "module"):
		if combined_used and key in {"string", "module"}:
			continue
		for text in _as_text_list(plugin_details.get(key)):
			if text not in values:
				values.append(text)

	for key, raw in plugin_details.items():
		if key in {"version", "string", "module", "certainty"}:
			continue
		for text in _as_text_list(raw):
			if text not in values:
				values.append(text)

	return values


def _collect_technologies(entries: List[Dict[str, Any]]) -> List[Dict[str, str]]:
	"""Convert WhatWeb entries into [{name, value}, ...] without duplicates."""

	technologies: List[Dict[str, str]] = []
	seen_pairs = set()

	for entry in entries:
		plugins = entry.get("plugins", {})
		if not isinstance(plugins, dict):
			continue

		for plugin_name, plugin_details in plugins.items():
			values = _extract_plugin_values(plugin_details)

			if not values:
				pair = (plugin_name, "")
				if pair in seen_pairs:
					continue
				seen_pairs.add(pair)
				technologies.append({"name": plugin_name, "value": "", "version": ""})
				continue

			for value in values:
				pair = (plugin_name, value)
				if pair in seen_pairs:
					continue
				seen_pairs.add(pair)
				technologies.append({"name": plugin_name, "value": value, "version": value})

	technologies.sort(key=lambda item: (item["name"].lower(), item.get("value", "")))
	return technologies


def _parse_whatweb_json_file(path: str, url: str) -> Dict[str, Any]:
	"""Read and normalize one WhatWeb JSON output file."""

	try:
		with open(path, "r", encoding="utf-8") as f:
			parsed = json.load(f)
	except Exception as exc:
		return {"entries": [], "error": f"Could not parse WhatWeb JSON output for {url}: {exc}"}

	if isinstance(parsed, list):
		entries = [item for item in parsed if isinstance(item, dict)]
		return {"entries": entries, "error": None}

	if isinstance(parsed, dict):
		return {"entries": [parsed], "error": None}

	return {"entries": [], "error": None}


def _run_whatweb_once(whatweb_path: str, url: str, timeout_seconds: int) -> Dict[str, Any]:
	"""Run WhatWeb for a single URL and return {'entries': [...], 'error': str|None}."""

	with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
		output_path = tmp.name

	command = [whatweb_path, f"--log-json={output_path}", url]

	try:
		result = subprocess.run(
			command,
			capture_output=True,
			text=True,
			timeout=timeout_seconds,
			check=False,
		)
	except subprocess.TimeoutExpired:
		return {"entries": [], "error": f"Timeout while fingerprinting {url}."}
	except Exception as exc:
		return {"entries": [], "error": f"WhatWeb failed for {url}: {exc}"}
	finally:
		if 'result' not in locals():
			_delete_temp_file(output_path)

	if result.returncode != 0:
		stderr = (result.stderr or "").strip()
		message = f"WhatWeb exited with code {result.returncode} for {url}"
		if stderr:
			message = f"{message}: {stderr}"
		else:
			message = f"{message}."
		_delete_temp_file(output_path)
		return {"entries": [], "error": message}

	parsed_result = _parse_whatweb_json_file(output_path, url)
	_delete_temp_file(output_path)
	return parsed_result


def run_whatweb_scan(
	target: str,
	timeout_seconds: int = 30,
	include_raw: bool = False,
) -> Dict[str, Any]:
	"""
	Execute WhatWeb and return structured technology fingerprinting results.

	If WhatWeb is unavailable or returns no parsable output, this function returns
	a structured error status instead of raising.
	"""

	whatweb_path = shutil.which("whatweb")
	if not whatweb_path:
		result = {
			"enabled": False,
			"tool": "whatweb",
			"status": "unavailable",
			"error": "WhatWeb is not installed or not available in PATH.",
			"targets_tested": [],
			"technologies": [],
		}
		if include_raw:
			result["raw_entries"] = []
		return result

	candidate_urls = _build_candidate_urls(target)
	all_entries: List[Dict[str, Any]] = []
	errors: List[str] = []

	for url in candidate_urls:
		scan_result = _run_whatweb_once(whatweb_path, url, timeout_seconds)
		all_entries.extend(scan_result["entries"])

		error_message = scan_result["error"]
		if error_message:
			errors.append(error_message)

	technologies = _collect_technologies(all_entries)

	status = "ok"
	if not technologies:
		status = "no-findings"
	if errors and not technologies:
		status = "error"

	result = {
		"enabled": True,
		"tool": "whatweb",
		"status": status,
		"targets_tested": candidate_urls,
		"technologies": technologies,
		"errors": errors,
	}

	if include_raw:
		result["raw_entries"] = all_entries

	return result
