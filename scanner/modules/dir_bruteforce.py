"""
dir_bruteforce.py
Performs basic optional web directory enumeration.
"""

from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import requests


DEFAULT_PATHS = [
	"admin",
	"login",
	"dashboard",
	"uploads",
	"backup",
	"config",
	"phpinfo.php",
	".env",
	"robots.txt",
	"sitemap.xml",
	"api",
	"test",
]

INTERESTING_STATUS_CODES = {
	200,
	201,
	202,
	204,
	301,
	302,
	307,
	308,
	401,
	403,
}


def _build_candidate_urls(target: str) -> List[str]:
	"""Return one or two base URLs to test."""

	parsed = urlparse(target)
	if parsed.scheme and parsed.netloc:
		return [target.rstrip("/")]

	host = target.strip().strip("/")
	return [f"https://{host}", f"http://{host}"]


def _normalize_paths(paths: Optional[List[str]]) -> List[str]:
	"""Sanitize and deduplicate candidate path fragments."""

	source = paths if paths else DEFAULT_PATHS
	cleaned: List[str] = []

	for value in source:
		item = str(value).strip().strip("/")
		if item and item not in cleaned:
			cleaned.append(item)

	return cleaned


def run_directory_enumeration(
	target: str,
	paths: Optional[List[str]] = None,
	timeout_seconds: int = 5,
) -> Dict[str, Any]:
	"""
	Enumerate common or user-provided directories/files for a web target.

	Returns structured findings and errors instead of raising exceptions.
	"""

	candidate_urls = _build_candidate_urls(target)
	candidate_paths = _normalize_paths(paths)

	findings: List[Dict[str, Any]] = []
	errors: List[str] = []
	seen_urls = set()

	headers = {"User-Agent": "AttackSurfaceScanner/1.0"}

	for base_url in candidate_urls:
		for path in candidate_paths:
			url = f"{base_url}/{path}"

			try:
				response = requests.get(
					url,
					timeout=timeout_seconds,
					allow_redirects=True,
					headers=headers,
				)
			except requests.RequestException as exc:
				errors.append(f"{url}: {exc}")
				continue

			if response.status_code not in INTERESTING_STATUS_CODES:
				continue

			if url in seen_urls:
				continue

			seen_urls.add(url)
			findings.append(
				{
					"url": url,
					"path": path,
					"status_code": response.status_code,
					"reason": response.reason,
					"content_length": response.headers.get("Content-Length", ""),
					"location": response.headers.get("Location", ""),
				}
			)

	findings.sort(key=lambda item: (item["status_code"], item["url"]))

	status = "ok"
	if not findings:
		status = "no-findings"
	if errors and not findings:
		status = "error"

	return {
		"enabled": True,
		"tool": "directory-enumeration",
		"status": status,
		"targets_tested": candidate_urls,
		"paths_tested": len(candidate_paths),
		"findings": findings,
		"errors": errors,
	}
