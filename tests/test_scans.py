from pathlib import Path

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

    checker = create_checker(load_dotenv_file=False)

    assert checker.vt_api_key == "vt-key"
    assert checker.abuse_api_key == "abuse-key"


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
