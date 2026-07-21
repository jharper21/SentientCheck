from pathlib import Path

import pytest

from sentientcheck.core import REQUEST_TIMEOUT, ReputationChecker
from sentientcheck.config import create_checker


def test_assess_risk_marks_clean_when_no_sources_flagged():
    checker = ReputationChecker("vt-key")
    results = {
        "vt": {
            "data": {
                "attributes": {
                    "last_analysis_stats": {
                        "malicious": 0,
                        "suspicious": 0,
                        "undetected": 80,
                        "harmless": 10,
                    }
                }
            }
        }
    }

    assessment = checker.assess_risk("ip", results)

    assert assessment["rating"] == "CLEAN"
    assert assessment["score"] == 0
    assert assessment["sources_checked"] == 1


def test_assess_risk_marks_urlhaus_online_url_malicious():
    checker = ReputationChecker("vt-key")
    results = {
        "urlhaus": {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
        }
    }

    assessment = checker.assess_risk("url", results)

    assert assessment["rating"] == "MALICIOUS"
    assert assessment["score"] == 100
    assert "URLhaus" in assessment["factors"][0]


def test_calculate_hash_returns_sha256(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sentientcheck")
    checker = ReputationChecker("vt-key")

    assert checker.calculate_hash(sample) == (
        "547b78477d9790f8b25d1bf98c8ca7b3674a02ff"
        "27b8581e7439debe8ac8a6e6"
    )


def test_create_checker_uses_loaded_keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSE_API_KEY", "abuse-key")
    monkeypatch.setenv("ABUSECH_API_KEY", "abusech-key")

    checker = create_checker(load_dotenv_file=False)

    assert checker.vt_api_key == "vt-key"
    assert checker.abuse_api_key == "abuse-key"
    assert checker.abusech_api_key == "abusech-key"


def test_abusech_requests_share_auth_key(monkeypatch):
    calls = []

    class Response:
        status_code = 200

        def json(self):
            return {"query_status": "no_results"}

    def record_post(*args, **kwargs):
        calls.append(kwargs)
        return Response()

    monkeypatch.setattr("sentientcheck.core.requests.post", record_post)
    checker = ReputationChecker("vt-key", abusech_api_key="shared-key")

    checker.check_file_mb("a" * 64)
    checker.check_url_urlhaus("https://example.com")
    checker.check_file_urlhaus("a" * 64)

    assert len(calls) == 3
    assert all(call["headers"] == {"Auth-Key": "shared-key"} for call in calls)


def test_abusech_checks_are_skipped_without_auth_key(monkeypatch):
    def unexpected_post(*args, **kwargs):
        raise AssertionError("abuse.ch should not be called without an Auth-Key")

    monkeypatch.setattr("sentientcheck.core.requests.post", unexpected_post)
    checker = ReputationChecker("vt-key")

    assert checker.check_file_mb("a" * 64) is None
    assert checker.check_url_urlhaus("https://example.com") is None
    assert checker.check_file_urlhaus("a" * 64) is None


def test_provider_requests_use_timeout(monkeypatch):
    calls = []

    class Response:
        status_code = 404

        def json(self):
            return {}

    def record_get(*args, **kwargs):
        calls.append(("get", kwargs))
        return Response()

    def record_post(*args, **kwargs):
        calls.append(("post", kwargs))
        return Response()

    monkeypatch.setattr("sentientcheck.core.requests.get", record_get)
    monkeypatch.setattr("sentientcheck.core.requests.post", record_post)

    checker = ReputationChecker(
        "vt-key",
        "abuse-key",
        "urlscan-key",
        "hybrid-key",
        "urlhaus-key",
    )

    checker.check_ip_vt("127.0.0.1")
    checker.check_url_vt("https://example.com")
    checker.check_file_vt("a" * 64)
    checker.check_ip_abuse("127.0.0.1")
    checker.check_url_urlscan("https://example.com")
    checker.check_file_mb("a" * 64)
    checker.check_file_hybrid("a" * 64)
    checker.check_url_urlhaus("https://example.com")
    checker.check_file_urlhaus("a" * 64)

    assert len(calls) == 9
    assert all(kwargs["timeout"] == REQUEST_TIMEOUT for _, kwargs in calls)


from sentientcheck.scans import (
    check_file_hash,
    check_file_path,
    scan_directory,
    scan_targets,
)


class FakeChecker:
    def __init__(self):
        self.hash_requests = []

    def calculate_hash(self, path):
        self.hash_requests.append(Path(path))
        return "b" * 64

    def check_ip_vt(self, target):
        return {"data": {"attributes": {"last_analysis_stats": {"malicious": 1}}}}

    def check_ip_abuse(self, target):
        return None

    def check_url_vt(self, target):
        return {"error": "URL not previously analyzed. Submission required."}

    def check_url_urlscan(self, target):
        return None

    def check_url_urlhaus(self, target):
        return {"query_status": "no_results"}

    def check_file_vt(self, target):
        return {"error": "File hash not found in VirusTotal database."}

    def check_file_mb(self, target):
        return {"query_status": "hash_not_found"}

    def check_file_hybrid(self, target):
        return None

    def check_file_urlhaus(self, target):
        return {"query_status": "no_results"}

    def assess_risk(self, target_type, results):
        return {"rating": "CLEAN", "score": 0, "factors": [], "sources_checked": 1}


class HashFailureChecker(FakeChecker):
    def calculate_hash(self, path):
        self.hash_requests.append(Path(path))
        return None


def test_scan_targets_returns_structured_reports():
    reports = scan_targets(FakeChecker(), "ip", ["1.1.1.1", "8.8.8.8"], sleep_seconds=0)

    assert [report["target"] for report in reports] == ["1.1.1.1", "8.8.8.8"]
    assert reports[0]["type"] == "ip"
    assert reports[0]["assessment"]["rating"] == "CLEAN"
    assert "raw_results" in reports[0]


def test_scan_targets_rejects_unsupported_target_type():
    with pytest.raises(ValueError, match="Unsupported target type"):
        scan_targets(FakeChecker(), "domain", ["example.com"], sleep_seconds=0)


def test_scan_directory_rejects_invalid_directory(tmp_path):
    missing = tmp_path / "missing"

    with pytest.raises(ValueError, match="Invalid directory"):
        scan_directory(FakeChecker(), missing, sleep_seconds=0)


def test_check_file_hash_does_not_read_local_file():
    report = check_file_hash(FakeChecker(), "a" * 64)

    assert report["target"] == "a" * 64
    assert report["type"] == "file"
    assert report["raw_results"]["mb"]["query_status"] == "hash_not_found"


def test_scan_targets_file_uses_file_path_hashing(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"sentientcheck")
    checker = FakeChecker()

    reports = scan_targets(checker, "file", [sample], sleep_seconds=0)

    assert checker.hash_requests == [sample]
    assert reports[0]["target"] == "sample.bin"
    assert reports[0]["path"] == str(sample)
    assert reports[0]["sha256"] == "b" * 64
    assert reports[0]["raw_results"]["mb"]["query_status"] == "hash_not_found"


def test_scan_targets_file_string_path_hashes_file_not_contents(tmp_path):
    sample = tmp_path / "sample.bin"
    sample.write_text("line-one\nline-two\n", encoding="utf-8")
    checker = FakeChecker()

    reports = scan_targets(checker, "file", str(sample), sleep_seconds=0)

    assert checker.hash_requests == [sample]
    assert len(reports) == 1
    assert reports[0]["target"] == "sample.bin"
    assert reports[0]["sha256"] == "b" * 64


def test_check_file_path_returns_structured_error_when_hash_fails(tmp_path):
    sample = tmp_path / "unreadable.bin"
    checker = HashFailureChecker()

    report = check_file_path(checker, sample)

    assert report["target"] == "unreadable.bin"
    assert report["type"] == "file"
    assert "error" in report


def test_legacy_cli_module_imports_without_prompting():
    import SentientCheck

    assert hasattr(SentientCheck, "main")


def test_legacy_cli_does_not_keep_duplicate_reputation_checker():
    import SentientCheck

    assert not hasattr(SentientCheck, "ReputationChecker")
