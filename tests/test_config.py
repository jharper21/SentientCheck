from sentientcheck.config import (
    API_KEY_ENV_VARS,
    PROVIDERS,
    credential_status,
    load_api_keys,
    mask_secret,
)


def test_load_api_keys_reads_environment(monkeypatch):
    for env_var in API_KEY_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)
    monkeypatch.delenv("URLHAUS_API_KEY", raising=False)
    monkeypatch.setenv("VT_API_KEY", "vt-secret")
    monkeypatch.setenv("ABUSE_API_KEY", "abuse-secret")

    keys = load_api_keys(load_dotenv_file=False)

    assert keys["VT_API_KEY"] == "vt-secret"
    assert keys["ABUSE_API_KEY"] == "abuse-secret"
    assert keys["URLSCAN_API_KEY"] == ""


def test_load_api_keys_migrates_legacy_urlhaus_key(monkeypatch):
    monkeypatch.delenv("ABUSECH_API_KEY", raising=False)
    monkeypatch.setenv("URLHAUS_API_KEY", "legacy-abusech-secret")

    keys = load_api_keys(load_dotenv_file=False)

    assert keys["ABUSECH_API_KEY"] == "legacy-abusech-secret"


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
        "abusech",
    }
    assert PROVIDERS["virustotal"]["required"] is True
    assert PROVIDERS["abusech"]["env_var"] == "ABUSECH_API_KEY"


def test_build_env_content_preserves_key_order():
    from sentientcheck.setup_wizard import build_env_content

    content = build_env_content({
        "VT_API_KEY": "vt",
        "ABUSE_API_KEY": "",
        "URLSCAN_API_KEY": "urlscan",
        "HYBRID_API_KEY": "",
        "ABUSECH_API_KEY": "",
    })

    assert content.splitlines() == [
        "VT_API_KEY=vt",
        "ABUSE_API_KEY=",
        "URLSCAN_API_KEY=urlscan",
        "HYBRID_API_KEY=",
        "ABUSECH_API_KEY=",
    ]


def test_validate_credentials_marks_missing_and_unchecked(monkeypatch):
    from sentientcheck.setup_wizard import validate_credentials

    for env_var in API_KEY_ENV_VARS:
        monkeypatch.delenv(env_var, raising=False)

    result = validate_credentials(load_dotenv_file=False, perform_network_checks=False)

    assert result["virustotal"]["status"] == "missing"
    assert result["abusech"]["status"] == "missing"


def test_validate_abusech_uses_safe_authenticated_hash_lookup(monkeypatch):
    from sentientcheck.setup_wizard import validate_provider

    calls = []

    class Response:
        status_code = 200

        def json(self):
            return {"query_status": "hash_not_found"}

    def record_post(*args, **kwargs):
        calls.append((args, kwargs))
        return Response()

    monkeypatch.setattr("sentientcheck.setup_wizard.requests.post", record_post)

    result = validate_provider("abusech", "shared-key")

    assert result["status"] == "valid"
    assert calls[0][1]["headers"] == {"Auth-Key": "shared-key"}
    assert calls[0][1]["data"] == {"query": "get_info", "hash": "0" * 64}


def test_validate_abusech_rejects_api_key_error_response(monkeypatch):
    from sentientcheck.setup_wizard import validate_provider

    class Response:
        status_code = 200

        def json(self):
            return {"query_status": "no_api_key"}

    monkeypatch.setattr(
        "sentientcheck.setup_wizard.requests.post",
        lambda *args, **kwargs: Response(),
    )

    result = validate_provider("abusech", "invalid-key")

    assert result["status"] == "invalid"
    assert result["reason"] == "no_api_key"
