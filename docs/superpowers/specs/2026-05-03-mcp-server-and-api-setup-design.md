# SentientCheck MCP Server and API Setup Design

## Goal

Turn SentientCheck into an additive MCP-enabled tool while preserving the current project and CLI behavior. Claude, Codex, and other MCP clients should be able to run the same reputation checks the script supports today. New users should also have a guided, local setup path for third-party API keys.

The setup flow will not create or distribute generic shared API credentials. Each provider requires a user-owned account or token. SentientCheck will guide the user to the correct provider pages, explain what each key enables, write a local `.env`, and validate the configured keys where the provider API supports a lightweight check.

## Current State

The project currently has:

- `SentientCheck.py`: one interactive Python CLI containing API clients, risk assessment, parsing, report writers, and prompt-driven flows.
- `README.md`: setup and usage documentation for the CLI.

The existing implementation supports:

- IP reputation checks through VirusTotal and AbuseIPDB.
- URL reputation checks through VirusTotal, urlscan.io, and URLhaus.
- File reputation checks through VirusTotal, MalwareBazaar, Hybrid Analysis, and URLhaus.
- Single-target checks, file-list batch checks, directory file scanning, CSV reports, and JSON reports.

## Scope

This change is additive. Existing users should still be able to run SentientCheck as a script. The implementation can reorganize internals into modules, but the user-facing CLI should remain available.

In scope:

- Refactor reusable scan logic out of interactive prompts.
- Add an MCP server that exposes all current scan and report capabilities.
- Add a guided credential setup flow.
- Add local `.env` support and `.env.example`.
- Add documentation for Claude Desktop and Codex MCP configuration.
- Add focused tests for pure logic and credential/config behavior where practical.

Out of scope:

- Automatically issuing API keys.
- Shipping shared or generic API credentials.
- Uploading files to sandboxing services for analysis.
- Replacing the CLI with a GUI.
- Adding a hosted service or remote multi-user server.

## Architecture

Use a small package layout while keeping the current top-level script as a compatibility entry point.

Proposed files:

- `sentientcheck/__init__.py`: package metadata and public imports.
- `sentientcheck/core.py`: `ReputationChecker`, provider API calls, hash calculation, parsing helpers, risk assessment, and report serialization helpers.
- `sentientcheck/scans.py`: high-level scan functions that return structured dictionaries without prompting for input.
- `sentientcheck/config.py`: load environment variables and `.env`, report missing optional or required keys, and create checker instances.
- `sentientcheck/setup_wizard.py`: guided credential onboarding and validation.
- `sentientcheck/reports.py`: CSV and JSON report writing helpers, if report code is cleaner outside `core.py`.
- `sentientcheck_mcp.py`: MCP server entry point.
- `SentientCheck.py`: compatibility CLI wrapper around the new package functions.
- `requirements.txt`: Python dependencies, including the official Python MCP SDK package if it installs successfully in this environment.
- `.env.example`: safe placeholders for supported API keys.

## MCP Server

The MCP server should use stdio transport by default because that is the common path for local Claude Desktop and Codex integrations. The implementation should use the official Python MCP SDK package and verify the import locally before wiring the server. It should not prompt interactively during tool calls. If required credentials are missing, tools should return a clear structured error explaining how to run the setup wizard.

Tools:

- `check_ip(ip_address)`: run IP checks and return target, type, assessment, raw provider results, and checked sources.
- `check_url(url)`: run URL checks and return the same structured report shape.
- `check_file_hash(sha256)`: run file-hash checks without reading local files.
- `check_file_path(path)`: hash a local file and run file reputation checks.
- `scan_ip_list(path_or_targets)`: scan IPs from a path or explicit list.
- `scan_url_list(path_or_targets)`: scan URLs from a path or explicit list.
- `scan_directory(path)`: hash and scan regular files in a directory.
- `assess_risk(target_type, raw_results)`: expose the risk engine for clients that already have provider results.
- `save_csv_report(report_data, output_path=None)`: write a CSV report and return the path.
- `save_json_report(report_data, output_path=None)`: write a JSON report and return the path.
- `credential_status()`: report which keys are present without revealing secret values.
- `validate_credentials()`: run lightweight provider checks where supported and return status per provider.

Tool responses should be JSON-serializable dictionaries. Errors should be returned as structured data rather than raised into the MCP transport unless the server itself cannot continue.

## Credential Setup

The guided setup flow should be available as a normal Python command, for example:

```powershell
python -m sentientcheck.setup_wizard
```

The wizard should:

1. Explain that keys are user-owned and stored locally.
2. Show each provider, whether it is required, what feature it enables, and the signup/API-key URL.
3. Let the user paste keys, skip optional keys, or keep existing values.
4. Write `.env` in the project root using safe `KEY=value` syntax.
5. Validate configured keys where practical.
6. Print next-step MCP configuration guidance.

Provider guidance:

- VirusTotal: required for the baseline feature set; enables IP, URL, and file hash reputation.
- AbuseIPDB: optional; improves IP reputation.
- urlscan.io: optional; improves URL reputation.
- Hybrid Analysis: optional; improves file hash reputation.
- URLhaus: optional key; URL and payload lookups can run without a key but should use one if configured.
- MalwareBazaar: no key required for current hash lookup usage.

Validation should avoid submitting user URLs or files. Use harmless provider account/status endpoints when available, or a low-risk known public indicator only if needed. If validation is not reliable for a provider, return `not_checked` with a reason rather than pretending the key is valid.

## CLI Compatibility

`SentientCheck.py` should remain runnable. It can become a thin wrapper over the package. Existing interactive choices should continue to work:

- Check IP address or IP list.
- Check URL or URL list.
- Check single file or directory.
- Prompt to save CSV and JSON reports.

The CLI can also tell users to run the setup wizard when `VT_API_KEY` is missing instead of only prompting for it.

## Documentation

Update `README.md` to cover:

- Existing CLI usage.
- Guided setup wizard.
- Environment variables and `.env`.
- MCP server usage.
- Example Claude Desktop config.
- Example Codex MCP config.
- Security notes about third-party submissions and local secret storage.

Add `.env.example` with placeholders only.

## Testing and Verification

Minimum verification:

- Import the package successfully.
- Run `credential_status()` without real keys.
- Run risk assessment tests against fixture-like provider responses.
- Run report writer tests against temporary output paths.
- Start the MCP server enough to confirm tool registration, if the SDK exposes a local inspection path.
- Run the compatibility CLI import path without launching an endless prompt loop.

Network validation with real keys is optional because this repository should not require live credentials to pass local tests.

## Risks and Mitigations

- Risk: MCP tools accidentally block on `input()`.
  Mitigation: keep all MCP paths on non-interactive package functions.

- Risk: secrets leak through logs or tool responses.
  Mitigation: credential status only reports presence and validation state, never values.

- Risk: optional provider failures make scans look broken.
  Mitigation: return per-provider errors and still produce an assessment from available sources.

- Risk: refactor breaks the current CLI.
  Mitigation: keep the CLI wrapper small and test the high-level scan functions separately.

## Implementation Checks

- Verify the Python MCP SDK package name and import path locally before committing to the server entry point.
- Verify credential validation endpoints per provider during implementation. When a provider has no safe validation endpoint, return `not_checked` with a reason.
