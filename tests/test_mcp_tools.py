import sentientcheck_mcp


def test_mcp_module_exposes_expected_tool_functions():
    expected = {
        "check_ip",
        "check_url",
        "check_file_hash",
        "check_file_path",
        "scan_ip_list",
        "scan_url_list",
        "scan_directory_tool",
        "assess_risk_tool",
        "save_csv_report_tool",
        "save_json_report_tool",
        "credential_status_tool",
        "validate_credentials_tool",
    }

    for name in expected:
        assert hasattr(sentientcheck_mcp, name)
