"""
file_report.py
Exports detailed scan results to TXT and Markdown files.
"""

import json
from pathlib import Path
from typing import Any, Dict, List


def _text_summary(analysis: Dict[str, Any]) -> List[str]:
	summary = analysis.get("summary", {})
	risk_counts = summary.get("risk_counts", {})
	score = summary.get("attack_surface_score", {})

	return [
		"Risk Summary",
		"-" * 12,
		f"Total open ports: {summary.get('total_ports', 0)}",
		f"HIGH: {risk_counts.get('HIGH', 0)}",
		f"MEDIUM: {risk_counts.get('MEDIUM', 0)}",
		f"LOW: {risk_counts.get('LOW', 0)}",
		f"UNKNOWN: {risk_counts.get('UNKNOWN', 0)}",
		f"Attack surface score: {score.get('value', 0)} ({score.get('level', 'UNKNOWN')})",
		"",
	]


def _text_ports(analysis: Dict[str, Any]) -> List[str]:
	ports = analysis.get("ports", [])
	lines = [
		"Port Details",
		"-" * 12,
		"port/proto | state | service | product | version | risk",
		"-------------------------------------------------------",
	]

	if not isinstance(ports, list) or not ports:
		lines.append("No ports found.")
		lines.append("")
		return lines

	for item in ports:
		if not isinstance(item, dict):
			continue
		lines.append(
			f"{item.get('port', '')}/{item.get('protocol', '')} | {item.get('state', '')} | "
			f"{item.get('service', '')} | {item.get('product', '')} | {item.get('version', '')} | {item.get('risk', '')}"
		)

	lines.append("")
	return lines


def _text_web(analysis: Dict[str, Any]) -> List[str]:
	web = analysis.get("web")
	if not isinstance(web, dict):
		return []

	lines = [
		"Web Fingerprinting",
		"-" * 18,
		f"Tool: {web.get('tool', '')}",
		f"Status: {web.get('status', '')}",
	]

	error = web.get("error")
	if error:
		lines.append(f"Error: {error}")

	technologies = web.get("technologies", [])
	if isinstance(technologies, list) and technologies:
		lines.append("Technologies:")
		for tech in technologies:
			if isinstance(tech, dict):
				value = tech.get("value", "") or tech.get("version", "")
				lines.append(f"- {tech.get('name', '')}: {value}")
	else:
		lines.append("Technologies: none")

	errors = web.get("errors", [])
	if isinstance(errors, list) and errors:
		lines.append("Notes:")
		for msg in errors:
			lines.append(f"- {msg}")

	lines.append("")
	return lines


def _text_web_raw(analysis: Dict[str, Any]) -> List[str]:
	web = analysis.get("web")
	if not isinstance(web, dict):
		return []

	raw_entries = web.get("raw_entries", [])
	if not isinstance(raw_entries, list) or not raw_entries:
		return []

	lines = [
		"Web Fingerprinting Raw Entries",
		"-" * 30,
	]

	for index, entry in enumerate(raw_entries, start=1):
		lines.append(f"Entry {index}:")
		lines.append(json.dumps(entry, indent=2, ensure_ascii=False))
		lines.append("")

	return lines


def _text_dir_enum(analysis: Dict[str, Any]) -> List[str]:
	dir_enum = analysis.get("dir_enum")
	if not isinstance(dir_enum, dict):
		return []

	lines = [
		"Directory Enumeration",
		"-" * 21,
		f"Status: {dir_enum.get('status', '')}",
		f"Paths tested: {dir_enum.get('paths_tested', 0)}",
		f"Successful requests: {dir_enum.get('successful_requests', 0)}",
	]

	findings = dir_enum.get("findings", [])
	if isinstance(findings, list) and findings:
		lines.append("Findings:")
		for item in findings:
			if isinstance(item, dict):
				lines.append(
					f"- [{item.get('status_code', '')}] {item.get('url', '')} "
					f"(redirect: {item.get('location', '')})"
				)
	else:
		lines.append("Findings: none")

	errors = dir_enum.get("errors", [])
	if isinstance(errors, list) and errors:
		lines.append("Notes:")
		for msg in errors:
			lines.append(f"- {msg}")

	lines.append("")
	return lines


def _text_diff(analysis: Dict[str, Any]) -> List[str]:
	diff = analysis.get("diff")
	if not isinstance(diff, dict):
		return []

	summary = diff.get("summary", {})
	lines = [
		"Change Detection",
		"-" * 16,
		f"Previous open ports: {summary.get('previous_open_ports', 0)}",
		f"Current open ports: {summary.get('current_open_ports', 0)}",
		f"New ports open: {summary.get('new_ports_open', 0):+d}",
		f"New ports: {summary.get('new_ports', 0)}",
		f"Closed ports: {summary.get('closed_ports', 0)}",
		f"Changed services: {summary.get('changed_services', 0)}",
		"",
	]

	for key, title in [
		("new_ports", "New port entries"),
		("closed_ports", "Closed port entries"),
		("changed_services", "Changed services"),
	]:
		entries = diff.get(key, [])
		if isinstance(entries, list) and entries:
			lines.append(f"{title}:")
			for entry in entries:
				lines.append(f"- {entry}")
			lines.append("")

	return lines


def _build_text_report(target: str, profile: str, analysis: Dict[str, Any]) -> str:
	lines = [
		"Attack Surface Scanner Report",
		"=" * 32,
		f"Target: {target}",
		f"Profile: {profile}",
		"",
	]

	lines.extend(_text_summary(analysis))
	lines.extend(_text_ports(analysis))
	lines.extend(_text_web(analysis))
	lines.extend(_text_web_raw(analysis))
	lines.extend(_text_dir_enum(analysis))
	lines.extend(_text_diff(analysis))

	return "\n".join(lines)


def _build_markdown_report(target: str, profile: str, analysis: Dict[str, Any]) -> str:
	summary = analysis.get("summary", {})
	risk_counts = summary.get("risk_counts", {})
	score = summary.get("attack_surface_score", {})

	lines = [
		"# Attack Surface Scanner Report",
		"",
		f"- Target: {target}",
		f"- Profile: {profile}",
		"",
		"## Risk Summary",
		"",
		"| Metric | Value |",
		"|---|---:|",
		f"| Total open ports | {summary.get('total_ports', 0)} |",
		f"| HIGH | {risk_counts.get('HIGH', 0)} |",
		f"| MEDIUM | {risk_counts.get('MEDIUM', 0)} |",
		f"| LOW | {risk_counts.get('LOW', 0)} |",
		f"| UNKNOWN | {risk_counts.get('UNKNOWN', 0)} |",
		f"| Attack surface score | {score.get('value', 0)} ({score.get('level', 'UNKNOWN')}) |",
		"",
	]

	ports = analysis.get("ports", [])
	lines.extend(
		[
			"## Port Details",
			"",
			"| Port | Proto | State | Service | Product | Version | Risk |",
			"|---:|---|---|---|---|---|---|",
		]
	)
	if isinstance(ports, list) and ports:
		for item in ports:
			if isinstance(item, dict):
				lines.append(
					f"| {item.get('port', '')} | {item.get('protocol', '')} | {item.get('state', '')} | "
					f"{item.get('service', '')} | {item.get('product', '')} | {item.get('version', '')} | {item.get('risk', '')} |"
				)
	else:
		lines.append("| - | - | - | - | - | - | - |")
	lines.append("")

	web = analysis.get("web")
	if isinstance(web, dict):
		lines.extend(["## Web Fingerprinting", "", f"- Tool: {web.get('tool', '')}", f"- Status: {web.get('status', '')}"])
		if web.get("error"):
			lines.append(f"- Error: {web.get('error')}")
		lines.extend(["", "| Technology | Details |", "|---|---|"])
		techs = web.get("technologies", [])
		if isinstance(techs, list) and techs:
			for tech in techs:
				if isinstance(tech, dict):
					value = tech.get("value", "") or tech.get("version", "")
					lines.append(f"| {tech.get('name', '')} | {value} |")
		else:
			lines.append("| none | |")
		errors = web.get("errors", [])
		if isinstance(errors, list) and errors:
			lines.append("")
			lines.append("Notes:")
			for msg in errors:
				lines.append(f"- {msg}")
		lines.append("")

		raw_entries = web.get("raw_entries", [])
		if isinstance(raw_entries, list) and raw_entries:
			lines.append("## Web Fingerprinting Raw Entries")
			lines.append("")
			for index, entry in enumerate(raw_entries, start=1):
				lines.append(f"### Raw Entry {index}")
				lines.append("")
				lines.append("```json")
				lines.append(json.dumps(entry, indent=2, ensure_ascii=False))
				lines.append("```")
				lines.append("")

	dir_enum = analysis.get("dir_enum")
	if isinstance(dir_enum, dict):
		lines.extend(
			[
				"## Directory Enumeration",
				"",
				f"- Status: {dir_enum.get('status', '')}",
				f"- Paths tested: {dir_enum.get('paths_tested', 0)}",
				f"- Successful requests: {dir_enum.get('successful_requests', 0)}",
				"",
				"| Status | Path | URL | Redirect |",
				"|---:|---|---|---|",
			]
		)
		findings = dir_enum.get("findings", [])
		if isinstance(findings, list) and findings:
			for item in findings:
				if isinstance(item, dict):
					lines.append(
						f"| {item.get('status_code', '')} | {item.get('path', '')} | {item.get('url', '')} | {item.get('location', '')} |"
					)
		else:
			lines.append("| - | none | | |")
		errors = dir_enum.get("errors", [])
		if isinstance(errors, list) and errors:
			lines.append("")
			lines.append("Notes:")
			for msg in errors:
				lines.append(f"- {msg}")
		lines.append("")

	diff = analysis.get("diff")
	if isinstance(diff, dict):
		diff_summary = diff.get("summary", {})
		lines.extend(
			[
				"## Change Detection",
				"",
				"| Change Type | Count |",
				"|---|---:|",
				f"| Previous open ports | {diff_summary.get('previous_open_ports', 0)} |",
				f"| Current open ports | {diff_summary.get('current_open_ports', 0)} |",
				f"| New ports open | {diff_summary.get('new_ports_open', 0):+d} |",
				f"| New ports | {diff_summary.get('new_ports', 0)} |",
				f"| Closed ports | {diff_summary.get('closed_ports', 0)} |",
				f"| Changed services | {diff_summary.get('changed_services', 0)} |",
				"",
			]
		)

		for key, title in [
			("new_ports", "New Port Entries"),
			("closed_ports", "Closed Port Entries"),
			("changed_services", "Changed Services"),
		]:
			entries = diff.get(key, [])
			if isinstance(entries, list) and entries:
				lines.append(f"### {title}")
				lines.append("")
				for entry in entries:
					lines.append(f"- {entry}")
				lines.append("")

	return "\n".join(lines)


def export_reports(
	target: str,
	profile: str,
	analysis: Dict[str, Any],
	json_result_path: Path,
	formats: List[str],
) -> List[Path]:
	"""Export optional TXT/Markdown reports next to the saved JSON result."""

	created: List[Path] = []
	selected = {fmt.strip().lower() for fmt in formats if fmt.strip()}

	base_name = json_result_path.stem
	output_dir = json_result_path.parent

	if "txt" in selected:
		txt_path = output_dir / f"{base_name}.txt"
		txt_path.write_text(_build_text_report(target, profile, analysis), encoding="utf-8")
		created.append(txt_path)

	if "md" in selected or "markdown" in selected:
		md_path = output_dir / f"{base_name}.md"
		md_path.write_text(_build_markdown_report(target, profile, analysis), encoding="utf-8")
		created.append(md_path)

	return created
