# SentientCheck MCP Server and API Setup Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an MCP server and guided API credential setup while preserving the existing SentientCheck CLI behavior.

**Architecture:** Split the single script into a small importable `sentientcheck` package, then keep `SentientCheck.py` as a compatibility CLI wrapper. MCP tools and the setup wizard will call non-interactive package functions, so AI clients never block on `input()`.

**Tech Stack:** Python 3, `requests`, `python-dotenv`, official Python MCP SDK package, `pytest`.

---

## File Structure

- Create `sentientcheck/__init__.py`: package exports.
- Create `sentientcheck/core.py`: `ReputationChecker`, provider calls, hash calculation, risk assessment, parser helpers.
- Create `sentientcheck/config.py`: `.env` loading, credential status, checker construction.
- Create `sentientcheck/scans.py`: non-interactive high-level scan functions.
- Create `sentientcheck/reports.py`: CSV and JSON report writers.
- Create `sentientcheck/setup_wizard.py`: guided `.env` setup and credential validation command.
- Create `sentientcheck_mcp.py`: stdio MCP server entry point.
- Modify `SentientCheck.py`: keep interactive CLI, backed by package functions.
- Modify `README.md`: document CLI, wizard, `.env`, MCP client setup.
- Create `.env.example`: placeholder keys only.
- Create `requirements.txt`: runtime and test dependencies.
- Create `tests/test_config.py`, `tests/test_scans.py`, `tests/test_reports.py`, `tests/test_mcp_tools.py`.

---

### Task 1: Package Skeleton and Credential Config

**Files:**
- Create: `sentientcheck/__init__.py`
- Create: `sentientcheck/config.py`
- Create: `tests/test_config.py`
- Create: `requirements.txt`
- Create: `.env.example`

- [ ] **Step 1: Write failing config tests**

Create `tests/test_config.py`:

```python
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
```

- [ ] **Step 2: Run config tests to verify RED**

Run:

```powershell
python -m pytest tests/test_config.py -v
```

Expected: FAIL because `sentientcheck.config` does not exist.

- [ ] **Step 3: Add minimal config implementation**

Create `sentientcheck/__init__.py`:

```python
"""SentientCheck reputation checking package."""

__version__ = "0.1.0"
```

Create `sentientcheck/config.py`:

```python
import os
from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:
    load_dotenv = None


API_KEY_ENV_VARS = [
    "VT_API_KEY",
    "ABUSE_API_KEY",
    "URLSCAN_API_KEY",
    "HYBRID_API_KEY",
    "URLHAUS_API_KEY",
]

PROVIDERS = {
    "virustotal": {
        "name": "VirusTotal",
        "env_var": "VT_API_KEY",
        "required": True,
        "features": "IP, URL, and file hash reputation",
        "url": "https://www.virustotal.com/gui/my-apikey",
    },
    "abuseipdb": {
        "name": "AbuseIPDB",
        "env_var": "ABUSE_API_KEY",
        "required": False,
        "features": "IP reputation",
        "url": "https://www.abuseipdb.com/account/api",
    },
    "urlscan": {
        "name": "urlscan.io",
        "env_var": "URLSCAN_API_KEY",
        "required": False,
        "features": "URL reputation",
        "url": "https://urlscan.io/user/profile/",
    },
    "hybrid_analysis": {
        "name": "Hybrid Analysis",
        "env_var": "HYBRID_API_KEY",
        "required": False,
        "features": "file hash reputation",
        "url": "https://www.hybrid-analysis.com/profile",
    },
    "urlhaus": {
        "name": "URLhaus",
        "env_var": "URLHAUS_API_KEY",
        "required": False,
        "features": "URL and payload reputation",
        "url": "https://urlhaus.abuse.ch/api/",
    },
    "malwarebazaar": {
        "name": "MalwareBazaar",
        "env_var": None,
        "required": False,
        "features": "file hash reputation",
        "url": "https://bazaar.abuse.ch/api/",
    },
}


def project_root():
    return Path(__file__).resolve().parent.parent


def load_api_keys(load_dotenv_file=True, dotenv_path=None):
    if load_dotenv_file and load_dotenv is not None:
        load_dotenv(dotenv_path or project_root() / ".env")
    return {name: os.environ.get(name, "").strip() for name in API_KEY_ENV_VARS}


def mask_secret(value):
    if not value:
        return ""
    return "****" if len(value) <= 4 else "********"


def credential_status(load_dotenv_file=True):
    keys = load_api_keys(load_dotenv_file=load_dotenv_file)
    providers = {}
    for slug, meta in PROVIDERS.items():
        env_var = meta["env_var"]
        value = keys.get(env_var, "") if env_var else ""
        providers[slug] = {
            "name": meta["name"],
            "env_var": env_var,
            "required": meta["required"],
            "present": bool(value) if env_var else True,
            "value": mask_secret(value),
            "features": meta["features"],
            "url": meta["url"],
        }
    missing_required = [
        slug for slug, info in providers.items()
        if info["required"] and not info["present"]
    ]
    return {"providers": providers, "missing_required": missing_required}
```

Create `.env.example`:

```dotenv
VT_API_KEY=your_virustotal_key
ABUSE_API_KEY=your_abuseipdb_key
URLSCAN_API_KEY=your_urlscan_key
HYBRID_API_KEY=your_hybrid_analysis_key
URLHAUS_API_KEY=your_urlhaus_key
```

Create `requirements.txt`:

```text
requests>=2.31.0
python-dotenv>=1.0.0
mcp>=1.0.0
pytest>=8.0.0
```

- [ ] **Step 4: Run config tests to verify GREEN**

Run:

```powershell
python -m pytest tests/test_config.py -v
```

Expected: PASS.

---

### Task 2: Core Scanner Extraction

**Files:**
- Create: `sentientcheck/core.py`
- Modify: `sentientcheck/config.py`
- Create: `tests/test_scans.py`

- [ ] **Step 1: Write failing core tests**

Create `tests/test_scans.py`:

```python
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
        "b40c45bcd973abaec20e39eb1df4f8c37ec092a9"
        "83e7a7e0f3dc58c3072df871"
    )


def test_create_checker_uses_loaded_keys(monkeypatch):
    monkeypatch.setenv("VT_API_KEY", "vt-key")
    monkeypatch.setenv("ABUSE_API_KEY", "abuse-key")

    checker = create_checker(load_dotenv_file=False)

    assert checker.vt_api_key == "vt-key"
    assert checker.abuse_api_key == "abuse-key"
```

- [ ] **Step 2: Run scan tests to verify RED**

Run:

```powershell
python -m pytest tests/test_scans.py -v
```

Expected: FAIL because `sentientcheck.core` and `create_checker` do not exist.

- [ ] **Step 3: Move reusable scanner code**

Create `sentientcheck/core.py` by moving `ReputationChecker` from `SentientCheck.py`, keeping provider methods, `calculate_hash`, `assess_risk`, and parse helpers. Remove direct `sys.exit()` and interactive prompt logic from this module.

Add to `sentientcheck/config.py`:

```python
from sentientcheck.core import ReputationChecker


def create_checker(load_dotenv_file=True):
    keys = load_api_keys(load_dotenv_file=load_dotenv_file)
    return ReputationChecker(
        keys["VT_API_KEY"],
        keys["ABUSE_API_KEY"],
        keys["URLSCAN_API_KEY"],
        keys["HYBRID_API_KEY"],
        keys["URLHAUS_API_KEY"],
    )
```

- [ ] **Step 4: Run scan tests to verify GREEN**

Run:

```powershell
python -m pytest tests/test_scans.py -v
```

Expected: PASS.

---

### Task 3: Non-Interactive Scan and Report APIs

**Files:**
- Create: `sentientcheck/scans.py`
- Create: `sentientcheck/reports.py`
- Modify: `tests/test_scans.py`
- Create: `tests/test_reports.py`

- [ ] **Step 1: Write failing scan API tests**

Append to `tests/test_scans.py`:

```python
from sentientcheck.scans import check_file_hash, scan_targets


class FakeChecker:
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


def test_scan_targets_returns_structured_reports():
    reports = scan_targets(FakeChecker(), "ip", ["1.1.1.1", "8.8.8.8"], sleep_seconds=0)

    assert [report["target"] for report in reports] == ["1.1.1.1", "8.8.8.8"]
    assert reports[0]["type"] == "ip"
    assert reports[0]["assessment"]["rating"] == "CLEAN"
    assert "raw_results" in reports[0]


def test_check_file_hash_does_not_read_local_file():
    report = check_file_hash(FakeChecker(), "a" * 64)

    assert report["target"] == "a" * 64
    assert report["type"] == "file"
    assert report["raw_results"]["mb"]["query_status"] == "hash_not_found"
```

Create `tests/test_reports.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify RED**

Run:

```powershell
python -m pytest tests/test_scans.py tests/test_reports.py -v
```

Expected: FAIL because `sentientcheck.scans` and `sentientcheck.reports` do not exist.

- [ ] **Step 3: Implement scan APIs and report writers**

Create `sentientcheck/scans.py`:

```python
import os
import time
from pathlib import Path


def check_ip(checker, ip_address):
    results = {
        "vt": checker.check_ip_vt(ip_address),
        "abuse": checker.check_ip_abuse(ip_address),
    }
    return build_report(checker, ip_address, "ip", results)


def check_url(checker, url):
    results = {
        "vt": checker.check_url_vt(url),
        "urlscan": checker.check_url_urlscan(url),
        "urlhaus": checker.check_url_urlhaus(url),
    }
    return build_report(checker, url, "url", results)


def check_file_hash(checker, file_hash):
    results = {
        "vt": checker.check_file_vt(file_hash),
        "mb": checker.check_file_mb(file_hash),
        "hybrid": checker.check_file_hybrid(file_hash),
        "urlhaus": checker.check_file_urlhaus(file_hash),
    }
    return build_report(checker, file_hash, "file", results)


def check_file_path(checker, path):
    file_path = Path(path)
    file_hash = checker.calculate_hash(file_path)
    if not file_hash:
        return {
            "target": str(file_path),
            "type": "file",
            "error": "Could not calculate SHA256 hash for file.",
        }
    report = check_file_hash(checker, file_hash)
    report["target"] = file_path.name
    report["path"] = str(file_path)
    report["sha256"] = file_hash
    return report


def scan_targets(checker, target_type, targets, sleep_seconds=2):
    reports = []
    target_list = list(targets)
    for index, target in enumerate(target_list):
        if target_type == "ip":
            reports.append(check_ip(checker, target))
        elif target_type == "url":
            reports.append(check_url(checker, target))
        elif target_type == "file":
            reports.append(check_file_path(checker, target))
        else:
            raise ValueError(f"Unsupported target type: {target_type}")
        if sleep_seconds and index < len(target_list) - 1:
            time.sleep(sleep_seconds)
    return reports


def load_targets(path_or_targets):
    if isinstance(path_or_targets, (list, tuple)):
        return [str(item).strip() for item in path_or_targets if str(item).strip()]
    candidate = str(path_or_targets).strip().strip("'").strip('"')
    if os.path.isfile(candidate):
        with open(candidate, "r", encoding="utf-8") as handle:
            return [line.strip() for line in handle if line.strip()]
    return [candidate] if candidate else []


def scan_directory(checker, path, sleep_seconds=2):
    directory = Path(path)
    if not directory.is_dir():
        raise ValueError(f"Not a directory: {path}")
    files = [item for item in directory.iterdir() if item.is_file()]
    return scan_targets(checker, "file", files, sleep_seconds=sleep_seconds)


def build_report(checker, target, target_type, results):
    return {
        "target": str(target),
        "type": target_type,
        "assessment": checker.assess_risk(target_type, results),
        "raw_results": results,
    }
```

Create `sentientcheck/reports.py` by moving CSV and JSON writing logic from `SentientCheck.py`, changing each function to return a `Path` and accept `output_path=None`.

- [ ] **Step 4: Run tests to verify GREEN**

Run:

```powershell
python -m pytest tests/test_scans.py tests/test_reports.py -v
```

Expected: PASS.

---

### Task 4: Guided Setup Wizard and Credential Validation

**Files:**
- Create: `sentientcheck/setup_wizard.py`
- Modify: `sentientcheck/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing setup tests**

Append to `tests/test_config.py`:

```python
from sentientcheck.setup_wizard import build_env_content, validate_credentials


def test_build_env_content_preserves_key_order():
    content = build_env_content({
        "VT_API_KEY": "vt",
        "ABUSE_API_KEY": "",
        "URLSCAN_API_KEY": "urlscan",
        "HYBRID_API_KEY": "",
        "URLHAUS_API_KEY": "",
    })

    assert content.splitlines() == [
        "VT_API_KEY=vt",
        "ABUSE_API_KEY=",
        "URLSCAN_API_KEY=urlscan",
        "HYBRID_API_KEY=",
        "URLHAUS_API_KEY=",
    ]


def test_validate_credentials_marks_missing_and_unchecked(monkeypatch):
    monkeypatch.delenv("VT_API_KEY", raising=False)

    result = validate_credentials(load_dotenv_file=False, perform_network_checks=False)

    assert result["virustotal"]["status"] == "missing"
    assert result["malwarebazaar"]["status"] == "not_required"
```

- [ ] **Step 2: Run setup tests to verify RED**

Run:

```powershell
python -m pytest tests/test_config.py -v
```

Expected: FAIL because `sentientcheck.setup_wizard` does not exist.

- [ ] **Step 3: Implement setup wizard helpers**

Create `sentientcheck/setup_wizard.py`:

```python
from pathlib import Path

import requests

from sentientcheck.config import API_KEY_ENV_VARS, PROVIDERS, load_api_keys, project_root


def build_env_content(keys):
    return "\n".join(f"{name}={keys.get(name, '')}" for name in API_KEY_ENV_VARS) + "\n"


def validate_credentials(load_dotenv_file=True, perform_network_checks=True):
    keys = load_api_keys(load_dotenv_file=load_dotenv_file)
    results = {}
    for slug, meta in PROVIDERS.items():
        env_var = meta["env_var"]
        if env_var is None:
            results[slug] = {"status": "not_required", "reason": "No API key is required."}
            continue
        key = keys.get(env_var, "")
        if not key:
            results[slug] = {"status": "missing", "reason": f"{env_var} is not configured."}
            continue
        if not perform_network_checks:
            results[slug] = {"status": "not_checked", "reason": "Network validation was disabled."}
            continue
        results[slug] = validate_provider(slug, key)
    return results


def validate_provider(slug, key):
    try:
        if slug == "virustotal":
            response = requests.get(
                "https://www.virustotal.com/api/v3/users/current",
                headers={"x-apikey": key},
                timeout=10,
            )
            return status_from_response(response)
        if slug == "abuseipdb":
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": "127.0.0.1", "maxAgeInDays": "90"},
                timeout=10,
            )
            return status_from_response(response)
        if slug == "urlscan":
            response = requests.get(
                "https://urlscan.io/user/quotas/",
                headers={"API-Key": key},
                timeout=10,
            )
            return status_from_response(response)
        return {
            "status": "not_checked",
            "reason": "No safe lightweight validation endpoint is configured for this provider.",
        }
    except requests.RequestException as exc:
        return {"status": "error", "reason": str(exc)}


def status_from_response(response):
    if 200 <= response.status_code < 300:
        return {"status": "valid", "http_status": response.status_code}
    if response.status_code in (401, 403):
        return {"status": "invalid", "http_status": response.status_code}
    return {"status": "error", "http_status": response.status_code}


def write_env_file(keys, path=None):
    output_path = Path(path) if path else project_root() / ".env"
    output_path.write_text(build_env_content(keys), encoding="utf-8")
    return output_path


def main():
    existing = load_api_keys()
    keys = dict(existing)
    print("SentientCheck API setup")
    print("Keys are user-owned and stored locally in .env.")
    for slug, meta in PROVIDERS.items():
        env_var = meta["env_var"]
        print(f"\n{meta['name']}")
        print(f"Required: {'yes' if meta['required'] else 'no'}")
        print(f"Enables: {meta['features']}")
        print(f"Get key: {meta['url']}")
        if env_var is None:
            print("No key required.")
            continue
        current = existing.get(env_var, "")
        prompt = f"Enter {env_var}"
        if current:
            prompt += " or press Enter to keep current value"
        if not meta["required"]:
            prompt += " or type skip"
        value = input(prompt + ": ").strip()
        if value.lower() == "skip" and not meta["required"]:
            keys[env_var] = ""
        elif value:
            keys[env_var] = value
    path = write_env_file(keys)
    print(f"\nWrote credentials to {path}")
    print("Validation:")
    for slug, result in validate_credentials().items():
        print(f"- {PROVIDERS[slug]['name']}: {result['status']}")


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Run setup tests to verify GREEN**

Run:

```powershell
python -m pytest tests/test_config.py -v
```

Expected: PASS.

---

### Task 5: MCP Server Entry Point

**Files:**
- Create: `sentientcheck_mcp.py`
- Create: `tests/test_mcp_tools.py`
- Modify: `requirements.txt` if the MCP package import requires adjustment.

- [ ] **Step 1: Verify MCP SDK import path**

Run:

```powershell
python -c "from mcp.server.fastmcp import FastMCP; print(FastMCP)"
```

Expected: prints a `FastMCP` class. If it fails because `mcp` is not installed, install dependencies with `python -m pip install -r requirements.txt`, then rerun. If the import path changed, update this task and `sentientcheck_mcp.py` to the installed SDK's documented import path.

- [ ] **Step 2: Write failing MCP tool tests**

Create `tests/test_mcp_tools.py`:

```python
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
        "credential_status_tool",
        "validate_credentials_tool",
    }

    for name in expected:
        assert hasattr(sentientcheck_mcp, name)
```

- [ ] **Step 3: Run MCP tests to verify RED**

Run:

```powershell
python -m pytest tests/test_mcp_tools.py -v
```

Expected: FAIL because `sentientcheck_mcp.py` does not exist.

- [ ] **Step 4: Implement MCP server**

Create `sentientcheck_mcp.py`:

```python
from mcp.server.fastmcp import FastMCP

from sentientcheck.config import create_checker, credential_status
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
from sentientcheck.reports import save_csv_report, save_json_report


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
def scan_ip_list(path_or_targets):
    checker, error = checker_or_error()
    if error:
        return error
    return scan_targets(checker, "ip", load_targets(path_or_targets))


@mcp.tool()
def scan_url_list(path_or_targets):
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
def save_csv_report_tool(report_data, output_path=None):
    return {"path": str(save_csv_report(report_data, output_path))}


@mcp.tool()
def save_json_report_tool(report_data, output_path=None):
    return {"path": str(save_json_report(report_data, output_path))}


@mcp.tool()
def credential_status_tool():
    return credential_status()


@mcp.tool()
def validate_credentials_tool(perform_network_checks: bool = True):
    return validate_credentials(perform_network_checks=perform_network_checks)


if __name__ == "__main__":
    mcp.run()
```

- [ ] **Step 5: Run MCP tests to verify GREEN**

Run:

```powershell
python -m pytest tests/test_mcp_tools.py -v
```

Expected: PASS.

---

### Task 6: CLI Compatibility Wrapper

**Files:**
- Modify: `SentientCheck.py`
- Modify: `tests/test_scans.py`

- [ ] **Step 1: Write failing CLI import test**

Append to `tests/test_scans.py`:

```python
def test_legacy_cli_module_imports_without_prompting():
    import SentientCheck

    assert hasattr(SentientCheck, "main")
```

- [ ] **Step 2: Run import test to verify RED or current behavior**

Run:

```powershell
python -m pytest tests/test_scans.py::test_legacy_cli_module_imports_without_prompting -v
```

Expected: PASS if the current module already imports without prompting. If it passes, keep it as a regression test before refactoring.

- [ ] **Step 3: Replace top-level script with CLI wrapper**

Modify `SentientCheck.py` to:

- Import `create_checker`, `load_api_keys`, scan functions, and report writers.
- Preserve the current option menu.
- Use `python -m sentientcheck.setup_wizard` guidance when `VT_API_KEY` is absent.
- Keep report prompts and console summaries.
- Avoid duplicating provider API logic.

- [ ] **Step 4: Run CLI import test and package tests**

Run:

```powershell
python -m pytest tests/test_scans.py tests/test_reports.py tests/test_config.py -v
```

Expected: PASS.

---

### Task 7: README and Client Configuration Docs

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Add sections for:

- `pip install -r requirements.txt`
- `python -m sentientcheck.setup_wizard`
- `python SentientCheck.py`
- `python sentientcheck_mcp.py`
- Claude Desktop MCP JSON snippet using the absolute repo path.
- Codex MCP configuration guidance.
- Security notes: user-owned keys, local `.env`, third-party API submissions.

- [ ] **Step 2: Check README for stale script names**

Run:

```powershell
rg -n "reputation_checker|pip install requests|generic creds|shared API|SentientCheck.py|sentientcheck_mcp" README.md
```

Expected: no stale `reputation_checker.py` usage; README includes current commands.

---

### Task 8: Full Verification and Commit

**Files:**
- All changed files.

- [ ] **Step 1: Run full test suite**

Run:

```powershell
python -m pytest -v
```

Expected: PASS.

- [ ] **Step 2: Run import smoke checks**

Run:

```powershell
python -c "from sentientcheck.config import credential_status; print(credential_status(load_dotenv_file=False)['missing_required'])"
```

Expected: prints `['virustotal']` when no `VT_API_KEY` is set.

Run:

```powershell
python -c "import sentientcheck_mcp; print('mcp import ok')"
```

Expected: prints `mcp import ok`.

- [ ] **Step 3: Review git diff**

Run:

```powershell
git diff --stat
git diff -- README.md .env.example requirements.txt sentientcheck tests SentientCheck.py sentientcheck_mcp.py
```

Expected: changes match the approved additive design.

- [ ] **Step 4: Commit implementation**

Run:

```powershell
git add README.md .env.example requirements.txt SentientCheck.py sentientcheck sentientcheck_mcp.py tests docs/superpowers/plans/2026-05-03-mcp-server-and-api-setup.md
git commit -m "Add SentientCheck MCP server and setup wizard"
```

Expected: commit succeeds.
