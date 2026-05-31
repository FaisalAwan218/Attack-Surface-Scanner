"""
console_report.py
Formats and prints scan analysis results to the terminal using rich.
"""

from typing import Dict, Any
from rich.table import Table
from rich.console import Console

console = Console()


def print_report(target: str, analysis: Dict[str, Any]) -> None:
    """
    Print a formatted report for a single target.
    Expects analysis in the format returned by risk_engine.analyze_scan_results().
    """

    ports = analysis.get("ports", [])
    summary = analysis.get("summary", {})

    console.rule(f"[bold cyan]Attack Surface Summary for {target}[/bold cyan]")

    # Table with per-port details
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Port", style="bold")
    table.add_column("Proto")
    table.add_column("State")
    table.add_column("Service")
    table.add_column("Product")
    table.add_column("Version")
    table.add_column("Risk", style="bold")

    for p in ports:
        table.add_row(
            str(p.get("port", "")),
            p.get("protocol", ""),
            p.get("state", ""),
            p.get("service", ""),
            p.get("product", ""),
            p.get("version", ""),
            p.get("risk", ""),
        )

    console.print(table)

    # Risk summary section
    console.rule("[bold green]Risk Summary[/bold green]")
    risk_counts = summary.get("risk_counts", {})
    console.print(f"Total open ports: {summary.get('total_ports', 0)}")
    console.print(f"HIGH risk ports: {risk_counts.get('HIGH', 0)}")
    console.print(f"MEDIUM risk ports: {risk_counts.get('MEDIUM', 0)}")
    console.print(f"LOW risk ports: {risk_counts.get('LOW', 0)}")
    console.print(f"UNKNOWN risk ports: {risk_counts.get('UNKNOWN', 0)}")

    attack_surface_score = summary.get("attack_surface_score", {})
    if isinstance(attack_surface_score, dict):
        console.print(
            f"Attack surface score: {attack_surface_score.get('value', 0)} "
            f"({attack_surface_score.get('level', 'UNKNOWN')})"
        )

    # Optional web fingerprinting section
    web = analysis.get("web")
    if isinstance(web, dict):
        console.rule("[bold blue]Web Fingerprinting (WhatWeb)[/bold blue]")
        console.print(f"Status: {web.get('status', 'unknown')}")

        unavailable_reason = web.get("error")
        if unavailable_reason:
            console.print(f"Reason: {unavailable_reason}")

        technologies = web.get("technologies", [])
        if technologies:
            web_table = Table(show_header=True, header_style="bold cyan")
            web_table.add_column("Technology", style="bold")
            web_table.add_column("Details")

            for tech in technologies:
                detail = str(tech.get("value", "") or tech.get("version", ""))
                web_table.add_row(
                    str(tech.get("name", "")),
                    detail,
                )

            console.print(web_table)
        else:
            console.print("No technologies identified.")

        errors = web.get("errors", [])
        if errors:
            console.print("WhatWeb notes:")
            for msg in errors:
                console.print(f"- {msg}")

    # Optional directory enumeration section
    dir_enum = analysis.get("dir_enum")
    if isinstance(dir_enum, dict):
        console.rule("[bold yellow]Directory Enumeration[/bold yellow]")
        console.print(f"Status: {dir_enum.get('status', 'unknown')}")
        console.print(f"Paths tested: {dir_enum.get('paths_tested', 0)}")

        findings = dir_enum.get("findings", [])
        if findings:
            dir_table = Table(show_header=True, header_style="bold yellow")
            dir_table.add_column("Path", style="bold")
            dir_table.add_column("Status")
            dir_table.add_column("URL")
            dir_table.add_column("Redirect")

            for item in findings:
                dir_table.add_row(
                    str(item.get("path", "")),
                    str(item.get("status_code", "")),
                    str(item.get("url", "")),
                    str(item.get("location", "")),
                )

            console.print(dir_table)
        else:
            console.print("No interesting directories/files identified.")

        errors = dir_enum.get("errors", [])
        if errors:
            console.print("Directory enumeration notes:")
            for msg in errors[:5]:
                console.print(f"- {msg}")
            if len(errors) > 5:
                console.print(f"- ... and {len(errors) - 5} more")

    # Optional historical diff section
    diff = analysis.get("diff")
    if isinstance(diff, dict):
        console.rule("[bold white]History Change Detection[/bold white]")
        baseline = analysis.get("baseline", {})
        if isinstance(baseline, dict):
            base_target = baseline.get("target", "")
            base_profile = baseline.get("profile", "")
            base_timestamp = baseline.get("timestamp", "")
            console.print(
                f"Baseline: target={base_target}, profile={base_profile}, timestamp={base_timestamp}"
            )

        diff_summary = diff.get("summary", {})
        console.print(f"Previous open ports: {diff_summary.get('previous_open_ports', 0)}")
        console.print(f"Current open ports: {diff_summary.get('current_open_ports', 0)}")
        console.print(f"New ports open: {diff_summary.get('new_ports_open', 0):+d}")
        console.print(f"New ports: {diff_summary.get('new_ports', 0)}")
        console.print(f"Closed ports: {diff_summary.get('closed_ports', 0)}")
        console.print(f"Changed services: {diff_summary.get('changed_services', 0)}")

        new_ports = diff.get("new_ports", [])
        if new_ports:
            table_new = Table(show_header=True, header_style="bold green")
            table_new.add_column("Port", style="bold")
            table_new.add_column("Proto")
            table_new.add_column("Previous")
            table_new.add_column("Current")
            table_new.add_column("Service")
            table_new.add_column("Version")
            table_new.add_column("Risk")

            for item in new_ports:
                table_new.add_row(
                    str(item.get("port", "")),
                    str(item.get("protocol", "")),
                    "missing",
                    str(item.get("state", "")),
                    str(item.get("service", "")),
                    str(item.get("version", "")),
                    str(item.get("risk", "")),
                )

            console.print(table_new)
