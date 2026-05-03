from sentientcheck.config import (
    PROVIDERS,
    credential_status,
    load_api_keys,
    mask_secret,
)


def test_load_api_keys_reads_environment(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-secret")
    monkeypatch.setenv("ABUSE_API_KEY", "abuse-secret")

    keys = load_api_keys(load_dotenv_file=False)

    assert keys["VT_API_KEY"] == "vt-secret"
    assert keys["ABUSE_API_KEY"] == "abuse-secret"
    assert keys["URLSCAN_API_KEY"] == ""


def test_credential_status_reports_presence_without_values(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-secret")
    monkeypatch.delenv("ABUSE_API_KEY", raising=False)

    status = credential_status(load_dotenv_file=False)

    assert status["providers"]["virustotal"]["present"] is True
    assert status["providers"]["virustotal"]["required"] is True
    assert status["providers"]["virustotal"]["value"] == "********"
    assert status["providers"]["abuseipdb"]["present"] is False
    assert "vt-secret" not in str(status)


def test_mask_secret_preserves_absent_state():
    assert mask_secret("") == ""
    assert mask_secret(None) == ""
    assert mask_secret("abcd") == "****"
    assert mask_secret("abcdefghijkl") == "********"


def test_provider_metadata_contains_expected_services():
    assert set(PROVIDERS) == {
        "virustotal",
        "abuseipdb",
        "urlscan",
        "hybrid_analysis",
        "urlhaus",
        "malwarebazaar",
    }
    assert PROVIDERS["virustotal"]["required"] is True
    assert PROVIDERS["malwarebazaar"]["env_var"] is None
