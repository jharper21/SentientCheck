from typing import Any

from mcp.server.fastmcp import FastMCP

from sentientcheck.config import create_checker, credential_status
from sentientcheck.core import ReputationChecker
from sentientcheck.reports import save_csv_report, save_json_report
from sentientcheck.scans import (
    check_file_hash as run_check_file_hash,
    check_file_path as run_check_file_path,
    check_ip as run_check_ip,
    check_url as run_check_url,
    load_targets,
    scan_directory,
    scan_targets,
)
from sentientcheck.setup_wizard import validate_credentials


mcp = FastMCP("SentientCheck")


def missing_credentials_error():
    status = credential_status()
    if status["missing_required"]:
        return {
            "error": "Missing required API credentials.",
            "missing_required": status["missing_required"],
            "setup_command": "python -m sentientcheck.setup_wizard",
        }
    return None


def checker_or_error():
    error = missing_credentials_error()
    if error:
        return None, error
    return create_checker(), None


@mcp.tool()
def check_ip(ip_address: str):
    checker, error = checker_or_error()
    if error:
        return error
    return run_check_ip(checker, ip_address)


@mcp.tool()
def check_url(url: str):
    checker, error = checker_or_error()
    if error:
        return error
    return run_check_url(checker, url)


@mcp.tool()
def check_file_hash(sha256: str):
    checker, error = checker_or_error()
    if error:
        return error
    return run_check_file_hash(checker, sha256)


@mcp.tool()
def check_file_path(path: str):
    checker, error = checker_or_error()
    if error:
        return error
    return run_check_file_path(checker, path)


@mcp.tool()
def scan_ip_list(path_or_targets: Any):
    checker, error = checker_or_error()
    if error:
        return error
    return scan_targets(checker, "ip", load_targets(path_or_targets))


@mcp.tool()
def scan_url_list(path_or_targets: Any):
    checker, error = checker_or_error()
    if error:
        return error
    return scan_targets(checker, "url", load_targets(path_or_targets))


@mcp.tool()
def scan_directory_tool(path: str):
    checker, error = checker_or_error()
    if error:
        return error
    return scan_directory(checker, path)


@mcp.tool()
def assess_risk_tool(target_type: str, raw_results: dict):
    checker = ReputationChecker("")
    return checker.assess_risk(target_type, raw_results)


@mcp.tool()
def save_csv_report_tool(report_data: list, output_path: str | None = None, overwrite: bool = False):
    return {"path": str(save_csv_report(report_data, output_path, overwrite=overwrite))}


@mcp.tool()
def save_json_report_tool(report_data: list, output_path: str | None = None, overwrite: bool = False):
    return {"path": str(save_json_report(report_data, output_path, overwrite=overwrite))}


@mcp.tool()
def credential_status_tool():
    return credential_status()


@mcp.tool()
def validate_credentials_tool(perform_network_checks: bool = True):
    return validate_credentials(perform_network_checks=perform_network_checks)


if __name__ == "__main__":
    mcp.run()
