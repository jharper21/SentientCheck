from pathlib import Path

from sentientcheck.core import ReputationChecker
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
