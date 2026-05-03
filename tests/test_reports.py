import json
from pathlib import Path

import pytest

from sentientcheck.scans import check_file_path
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


class HashFailureChecker:
    def calculate_hash(self, path):
        return None


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


def test_save_json_report_uses_timestamped_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = save_json_report(sample_reports())

    assert isinstance(result, Path)
    assert result.name.startswith("report_1_1_1_1_")
    assert result.suffix == ".json"
    assert result.parent == Path(".")
    assert json.loads((tmp_path / result).read_text())[0]["target"] == "1.1.1.1"


def test_save_csv_report_uses_timestamped_default_path(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    result = save_csv_report(sample_reports())

    assert isinstance(result, Path)
    assert result.name.startswith("scan_results_")
    assert result.suffix == ".csv"
    assert result.parent == Path(".")
    assert "Target,Type,Rating" in (tmp_path / result).read_text()


def test_save_csv_report_writes_hash_error_report(tmp_path):
    failed_file = tmp_path / "unreadable.bin"
    report = check_file_path(HashFailureChecker(), failed_file)
    output = tmp_path / "report.csv"

    result = save_csv_report([report], output)

    assert result == output
    assert "unreadable.bin,file" in output.read_text()


def test_save_json_report_refuses_existing_output_by_default(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        save_json_report(sample_reports(), output)

    assert output.read_text(encoding="utf-8") == "existing"


def test_save_json_report_allows_existing_output_with_overwrite(tmp_path):
    output = tmp_path / "report.json"
    output.write_text("existing", encoding="utf-8")

    result = save_json_report(sample_reports(), output, overwrite=True)

    assert result == output
    assert json.loads(output.read_text())[0]["target"] == "1.1.1.1"


def test_save_csv_report_refuses_existing_output_by_default(tmp_path):
    output = tmp_path / "report.csv"
    output.write_text("existing", encoding="utf-8")

    with pytest.raises(FileExistsError):
        save_csv_report(sample_reports(), output)

    assert output.read_text(encoding="utf-8") == "existing"


def test_save_csv_report_allows_existing_output_with_overwrite(tmp_path):
    output = tmp_path / "report.csv"
    output.write_text("existing", encoding="utf-8")

    result = save_csv_report(sample_reports(), output, overwrite=True)

    assert result == output
    assert "Target,Type,Rating" in output.read_text()
