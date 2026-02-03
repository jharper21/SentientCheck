SentientCheck - Multi-Source Reputation ToolSentientCheck is a robust, multi-source reputation checking utility designed for InfoSec professionals, SOC analysts, and Threat Hunters. It aggregates intelligence from six major security APIs to provide a comprehensive risk assessment for IPs, URLs, and Files.It supports single-target analysis, batch processing via file lists, and directory scanning, with automated reporting in CSV and JSON formats.🚀 FeaturesMulti-Source Intelligence: Cross-references targets against multiple databases simultaneously.Risk Assessment Engine: Aggregates data to calculate a unified Confidence Score (0-100) and Verdict (Clean, Suspicious, High Risk, Malicious).Batch Processing:Bulk scan IPs or URLs from text files.Recursively scan local directories for file reputation.Built-in rate limiting to respect API quotas.Reporting:CSV: Spreadsheet-friendly summary of all scanned items.JSON: Full detailed report including raw API responses.🛡️ IntegrationsTarget TypeSource APIs UsedIP AddressVirusTotal v3, AbuseIPDBURLVirusTotal v3, urlscan.io, URLhausFile / HashVirusTotal v3, MalwareBazaar, Hybrid Analysis, URLhaus📋 PrerequisitesPython 3.6+requests library⚙️ InstallationClone the repository:git clone [https://github.com/yourusername/sentientcheck.git](https://github.com/yourusername/sentientcheck.git)
cd sentientcheck
Install dependencies:pip install requests
🔑 Configuration (API Keys)You can provide API keys via Environment Variables (recommended) or enter them interactively when the script runs.Environment Variables SetupSetting these allows the script to run without prompting for credentials every time.Linux / Mac:export VT_API_KEY="your_virustotal_key"
export ABUSE_API_KEY="your_abuseipdb_key"
export URLSCAN_API_KEY="your_urlscan_key"
export HYBRID_API_KEY="your_hybrid_analysis_key"
export URLHAUS_API_KEY="your_urlhaus_key"
Windows (PowerShell):$env:VT_API_KEY="your_virustotal_key"
$env:ABUSE_API_KEY="your_abuseipdb_key"
$env:URLSCAN_API_KEY="your_urlscan_key"
$env:HYBRID_API_KEY="your_hybrid_analysis_key"
$env:URLHAUS_API_KEY="your_urlhaus_key"
Note: VirusTotal is the only mandatory API key. Others are optional but highly recommended for better accuracy.💻 UsageRun the script:python reputation_checker.py
ModesCheck IP Address(es): Enter a single IP (e.g., 1.1.1.1) or a path to a text file containing one IP per line.Check URL(s): Enter a single URL (e.g., http://example.com) or a path to a text file containing URLs.Check File(s): Enter a file path for a single hash check, or a directory path to hash and check every file in that folder.Batch ScanningTo scan multiple targets, create a text file (e.g., suspects.txt):192.168.1.50
10.0.0.5
8.8.8.8
Then select Option 1 and provide the path: suspects.txt.📊 Output ExamplesConsole Output:############################################################
   FINAL REPORT: [http://malicious-site.example](http://malicious-site.example)
############################################################
Target Type:     URL
Sources Checked: 3
------------------------------------------------------------
GENERAL RATING:  [!!!] MALICIOUS
CONFIDENCE:      100/100
------------------------------------------------------------
Risk Factors:
 - VirusTotal: 18 engines flagged this URL
 - urlscan.io: Verdict is MALICIOUS
 - URLhaus: URL is listed in database as malware_download
📝 LicenseMIT⚠️ DisclaimerThis tool is for educational and professional defensive security purposes only. Ensure you have authorization before scanning files or URLs that may contain sensitive data, as hashes and URLs are submitted to third-party services.