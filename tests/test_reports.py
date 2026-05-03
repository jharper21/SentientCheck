import json

from sentientcheck.reports import save_csv_report, save_json_report


def sample_reports():
    return [
        {
            "target": "1.1.1.1",
            "type": "ip",
            "assessment": {
                "rating": "CLEAN",
                "score": 0,
                "sources_checked": 1,
                "factors": [],
            },
            "raw_results": {},
        }
    ]


def test_save_json_report_writes_requested_path(tmp_path):
    output = tmp_path / "report.json"

    result = save_json_report(sample_reports(), output)

    assert result == output
    assert json.loads(output.read_text())[0]["target"] == "1.1.1.1"


def test_save_csv_report_writes_requested_path(tmp_path):
    output = tmp_path / "report.csv"

    result = save_csv_report(sample_reports(), output)

    assert result == output
    assert "Target,Type,Rating" in output.read_text()
