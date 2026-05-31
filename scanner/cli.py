"""
cli.py
Command-line entrypoint for the Attack Surface Scanner.
Parses arguments, runs the selected scan profile, and shows/saves results.
"""

import argparse
from typing import List, Optional

from scanner.utils import (
    is_valid_ip,
    is_probably_domain,
    normalize_target,
    print_error,
    print_info,
)
from .analysis.diff_engine import compare_analyses
from .analysis.risk_engine import analyze_scan_results
from .config import SCAN_PROFILES
from .modules.dir_bruteforce import run_directory_enumeration
from .modules.nmap_scanner import run_nmap_scan
from .modules.web_whatweb import run_whatweb_scan
from .reporting.console_report import print_report
from .reporting.file_report import export_reports
from .storage.filesystem import (
    load_latest_scan_result,
    load_scan_result_from_path,
    save_scan_result,
)


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Attack Surface Scanner - Nmap-based attack surface mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python -m scanner.cli --target example.com --profile network-basic\n"
            "  python -m scanner.cli --target https://example.com --profile web-focused --dir-enum\n"
            "  python -m scanner.cli --target example.com --profile network-basic --compare-latest\n"
            "  python -m scanner.cli --target example.com --profile network-basic --compare-file results/20260425T035339Z_example.com_network-basic.json\n"
            "  python -m scanner.cli --target example.com --profile web-focused --web-raw --export-formats txt,md\n"
        ),
    )
    parser.add_argument(
        "--target",
        required=True,
        metavar="HOST_OR_URL",
        help=(
            "Target to scan. Accepts a domain, IP address, or full URL. "
            "Examples: example.com, https://example.com, 192.168.1.10."
        ),
    )
    parser.add_argument(
        "--profile",
        default="network-basic",
        metavar="PROFILE",
        help=(
            f"Scan profile to use. Available profiles: {', '.join(SCAN_PROFILES.keys())}. "
            "Use network-basic for port scanning only, or web-focused for WhatWeb plus optional web checks."
        ),
    )
    parser.add_argument(
        "--dir-enum",
        action="store_true",
        help=(
            "Enable optional directory enumeration against the target web host. "
            "Best used with --profile web-focused."
        ),
    )
    parser.add_argument(
        "--dir-wordlist",
        metavar="FILE",
        help="Optional path to a custom wordlist for directory enumeration (one path per line).",
    )
    parser.add_argument(
        "--compare-latest",
        action="store_true",
        help=(
            "Compare the current scan with the latest saved JSON for the same target and profile. "
            "Use this when you want the newest baseline automatically."
        ),
    )
    parser.add_argument(
        "--compare-file",
        metavar="JSON_FILE",
        help="Path to a specific previous scan JSON file to compare against.",
    )
    parser.add_argument(
        "--export-formats",
        metavar="LIST",
        help="Optional comma-separated formats for file export: txt,md",
    )
    parser.add_argument(
        "--web-timeout",
        type=int,
        default=30,
        metavar="SECONDS",
        help="Timeout in seconds for WhatWeb fingerprinting requests (default: 30).",
    )
    parser.add_argument(
        "--dir-timeout",
        type=int,
        default=5,
        metavar="SECONDS",
        help="Timeout in seconds for each directory enumeration request (default: 5).",
    )
    parser.add_argument(
        "--web-raw",
        action="store_true",
        help="Include raw WhatWeb JSON plugin entries in saved/exported reports.",
    )

    return parser.parse_args()


def _load_wordlist(path: str) -> List[str]:
    """Load a simple newline-delimited wordlist for directory enumeration."""

    with open(path, "r", encoding="utf-8") as file_obj:
        words = [line.strip() for line in file_obj.readlines()]

    return [word for word in words if word and not word.startswith("#")]


def _load_baseline_scan(
    compare_latest: bool,
    compare_file: Optional[str],
    target: str,
    profile_name: str,
) -> Optional[dict]:
    """Load baseline scan payload based on user options."""

    if compare_file:
        return load_scan_result_from_path(compare_file)
    if compare_latest:
        return load_latest_scan_result(target, profile_name)
    return None


def main() -> None:
    """Main CLI workflow: validate target, run scan, analyze, report, save."""

    args = parse_args()
    raw_target = args.target
    profile_name = args.profile
    dir_enum_enabled = args.dir_enum
    dir_wordlist = args.dir_wordlist
    compare_latest = args.compare_latest
    compare_file = args.compare_file
    export_formats_raw = args.export_formats
    web_timeout = max(1, args.web_timeout)
    dir_timeout = max(1, args.dir_timeout)
    include_web_raw = args.web_raw

    target = normalize_target(raw_target)

    if not (is_valid_ip(target) or is_probably_domain(target)):
        print_error("Invalid target. Provide a valid IP address or domain.")
        return

    if profile_name not in SCAN_PROFILES:
        print_error(f"Unknown profile: {profile_name}")
        return

    print_info(f"Starting scan for target: {target} with profile: {profile_name}")

    # 1) Run Nmap scan
    scan_results = run_nmap_scan(target, profile_name)

    # 2) Analyze risk
    analysis = analyze_scan_results(scan_results)

    # 3) Optional web fingerprinting for web-focused profile
    if SCAN_PROFILES[profile_name].get("run_web", False):
        print_info("Running WhatWeb technology fingerprinting...")
        analysis["web"] = run_whatweb_scan(
            target,
            timeout_seconds=web_timeout,
            include_raw=include_web_raw,
        )

        if dir_enum_enabled:
            custom_paths = None
            if dir_wordlist:
                try:
                    custom_paths = _load_wordlist(dir_wordlist)
                    print_info(f"Loaded {len(custom_paths)} paths from custom wordlist.")
                except Exception as exc:
                    print_error(f"Could not read wordlist '{dir_wordlist}': {exc}")
                    return

            print_info("Running optional directory enumeration...")
            analysis["dir_enum"] = run_directory_enumeration(
                target,
                paths=custom_paths,
                timeout_seconds=dir_timeout,
            )
    elif dir_enum_enabled:
        print_info("Directory enumeration skipped because current profile is not web-focused.")

    # 4) Optional historical comparison
    baseline_payload = _load_baseline_scan(compare_latest, compare_file, target, profile_name)
    if compare_latest or compare_file:
        if baseline_payload and isinstance(baseline_payload.get("data"), dict):
            baseline_analysis = baseline_payload.get("data", {})
            analysis["diff"] = compare_analyses(analysis, baseline_analysis)
            analysis["baseline"] = {
                "timestamp": baseline_payload.get("timestamp"),
                "profile": baseline_payload.get("profile"),
                "target": baseline_payload.get("target"),
            }
            print_info("Historical comparison completed.")
        else:
            print_info("No valid baseline scan found for comparison.")

    # 5) Print console report
    print_report(target, analysis)

    # 6) Save analysis to JSON file
    path = save_scan_result(target, profile_name, analysis)
    print_info(f"Scan result saved to: {path}")

    # 7) Optional TXT/Markdown export
    if export_formats_raw:
        export_formats = [item.strip() for item in export_formats_raw.split(",") if item.strip()]
        generated_paths = export_reports(target, profile_name, analysis, path, export_formats)
        if generated_paths:
            print_info("Exported reports:")
            for report_path in generated_paths:
                print_info(f" - {report_path}")
        else:
            print_info("No export files generated. Supported formats: txt,md")


if __name__ == "__main__":
    main()
