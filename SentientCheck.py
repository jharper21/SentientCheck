import os
import sys

from sentientcheck import core
from sentientcheck.config import load_api_keys
from sentientcheck.reports import save_csv_report, save_json_report
from sentientcheck.scans import (
    check_file_path,
    load_targets,
    scan_directory,
    scan_targets,
)


def build_checker():
    keys = load_api_keys()
    vt_key = keys["VT_API_KEY"]
    if not vt_key:
        print("[!] VirusTotal API Key is required for baseline scanning.")
        print("[*] Run `python -m sentientcheck.setup_wizard` for guided API setup.")
        vt_key = input("Enter VirusTotal API Key for this session, or press Enter to exit: ").strip()
        if not vt_key:
            sys.exit(1)

    return core.ReputationChecker(
        vt_key,
        keys["ABUSE_API_KEY"],
        keys["URLSCAN_API_KEY"],
        keys["HYBRID_API_KEY"],
        keys["ABUSECH_API_KEY"],
    )


def print_detail_summary(checker, report):
    results = report.get("raw_results", {})
    target_type = report.get("type")
    print("--- Detail Summary ---")
    if "vt" in results:
        checker.parse_vt_report(results["vt"])
    if "abuse" in results:
        checker.parse_abuse_report(results["abuse"])
    if "urlscan" in results:
        checker.parse_urlscan_report(results["urlscan"])
    if "mb" in results:
        checker.parse_mb_report(results["mb"])
    if "hybrid" in results:
        checker.parse_hybrid_report(results["hybrid"])
    if "urlhaus" in results:
        checker.parse_urlhaus_report(results["urlhaus"], is_file=(target_type == "file"))


def run_reports(checker, target_type, targets):
    reports = scan_targets(checker, target_type, targets)
    for report in reports:
        if "error" in report:
            print(f"[!] {report['target']}: {report['error']}")
        checker.print_summary_report(report["target"], report["type"], report["assessment"])
        if len(reports) == 1:
            print_detail_summary(checker, report)
    return reports


def prompt_for_reports(reports):
    if not reports:
        return

    print("\n" + "=" * 30)
    print("   BATCH SCAN COMPLETE" if len(reports) > 1 else "   SCAN COMPLETE")
    print("=" * 30)

    if input("Save results to CSV? (y/n): ").lower() == "y":
        path = save_csv_report(reports)
        print(f"[+] CSV report saved to: {path}")

    if input("Save full details to JSON? (y/n): ").lower() == "y":
        path = save_json_report(reports)
        print(f"[+] Full JSON report saved to: {path}")


def main():
    print("-" * 60)
    print("   SentientCheck - Multi-Source Reputation Tool")
    print("-" * 60)

    checker = build_checker()

    while True:
        print("\nOptions:")
        print("1. Check IP Address(es) (Single or File List)")
        print("2. Check URL(s) (Single or File List)")
        print("3. Check File(s) (Single File or Directory)")
        print("4. Exit")

        choice = input("\nSelect option (1-4): ").strip()

        if choice == "4":
            print("Exiting...")
            break

        try:
            if choice == "1":
                inp = input("Enter IP or path to file list: ").strip().strip("'").strip('"')
                reports = run_reports(checker, "ip", load_targets(inp))
            elif choice == "2":
                inp = input("Enter URL or path to file list: ").strip().strip("'").strip('"')
                reports = run_reports(checker, "url", load_targets(inp))
            elif choice == "3":
                inp = input("Enter file path or directory: ").strip().strip("'").strip('"')
                if os.path.isdir(inp):
                    reports = scan_directory(checker, inp)
                    for report in reports:
                        checker.print_summary_report(report["target"], report["type"], report["assessment"])
                elif os.path.isfile(inp):
                    report = check_file_path(checker, inp)
                    checker.print_summary_report(report["target"], report["type"], report["assessment"])
                    print_detail_summary(checker, report)
                    reports = [report]
                else:
                    print("[!] Invalid path.")
                    continue
            else:
                print("[!] Invalid selection")
                continue
        except ValueError as exc:
            print(f"[!] {exc}")
            continue

        prompt_for_reports(reports)


if __name__ == "__main__":
    main()
