# SentientCheck - Multi-Source Reputation Tool

SentientCheck is a multi-source reputation checking utility for defensive security work. It checks IPs, URLs, files, and file hashes against threat-intelligence providers, then returns a unified rating, confidence score, source details, and optional CSV/JSON reports.

SentientCheck can run as:

- An interactive CLI: `python SentientCheck.py`
- A local MCP server for clients such as Claude Desktop and Codex: `python sentientcheck_mcp.py`
- Importable Python modules under `sentientcheck/`

## Features

- Multi-source IP, URL, file, and hash reputation checks.
- Unified risk assessment with rating and confidence score.
- Single-target scans, IP/URL list scans, and directory file scans.
- CSV and JSON report writers.
- Guided API credential setup wizard.
- MCP tools for AI-client driven investigations.

## Integrations

| Target type | Source APIs |
| --- | --- |
| IP address | VirusTotal v3, AbuseIPDB |
| URL | VirusTotal v3, urlscan.io, URLhaus |
| File or hash | VirusTotal v3, MalwareBazaar, Hybrid Analysis, URLhaus |

VirusTotal is required for the baseline feature set. The other keys are optional but improve coverage. MalwareBazaar lookups do not require a key for the current hash lookup flow.

## Installation

```powershell
git clone https://github.com/jharper21/SentientCheck.git
cd SentientCheck
python -m pip install -r requirements.txt
```

Python 3.10+ is recommended.

## Guided API Setup

Run the setup wizard:

```powershell
python -m sentientcheck.setup_wizard
```

The wizard explains each provider, shows where to get the key, lets you skip optional providers, writes a local `.env`, and validates configured keys where a safe lightweight validation endpoint is available.

SentientCheck does not create or ship generic shared API keys. Each key must come from your own provider account.

Supported environment variables:

```dotenv
VT_API_KEY=your_virustotal_key
ABUSE_API_KEY=your_abuseipdb_key
URLSCAN_API_KEY=your_urlscan_key
HYBRID_API_KEY=your_hybrid_analysis_key
URLHAUS_API_KEY=your_urlhaus_key
```

Use `.env.example` as the template.

## CLI Usage

```powershell
python SentientCheck.py
```

Modes:

1. Check one IP or a text file containing one IP per line.
2. Check one URL or a text file containing one URL per line.
3. Check one local file or every regular file in a directory.

At the end of each scan, the CLI can save a CSV summary and/or full JSON report.

## MCP Server

Start the local MCP server with stdio transport:

```powershell
python sentientcheck_mcp.py
```

Exposed MCP tools include:

- `check_ip`
- `check_url`
- `check_file_hash`
- `check_file_path`
- `scan_ip_list`
- `scan_url_list`
- `scan_directory_tool`
- `assess_risk_tool`
- `save_csv_report_tool`
- `save_json_report_tool`
- `credential_status_tool`
- `validate_credentials_tool`

If required credentials are missing, scan tools return a structured error with the setup command instead of prompting.

### Claude Desktop Example

Add an MCP server entry similar to this in Claude Desktop's MCP configuration. Adjust the path to your checkout.

```json
{
  "mcpServers": {
    "sentientcheck": {
      "command": "python",
      "args": [
        "C:\\Users\\fpsJH\\OneDrive\\Documents\\New project\\SentientCheck\\sentientcheck_mcp.py"
      ]
    }
  }
}
```

### Codex Example

Add a local MCP server command that runs the same script from this repository:

```toml
[mcp_servers.sentientcheck]
command = "python"
args = ["C:\\Users\\fpsJH\\OneDrive\\Documents\\New project\\SentientCheck\\sentientcheck_mcp.py"]
```

If your client supports a working directory field, set it to this repository root.

## Security Notes

- Keys are stored locally in `.env`; do not commit real API keys.
- URL and hash lookups may submit indicators to third-party services.
- File scans hash local files and submit hashes, not file contents.
- Report writers refuse to overwrite existing explicit output paths unless overwrite is requested by the caller.
- Run scans only for systems, URLs, and files you are authorized to investigate.

## Testing

```powershell
python -m pytest -v
```

## License

[MIT](https://choosealicense.com/licenses/mit/)
