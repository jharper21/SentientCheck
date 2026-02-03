# **SentientCheck \- Multi-Source Reputation Tool**

**SentientCheck** is a robust, multi-source reputation checking utility designed for InfoSec professionals, SOC analysts, and Threat Hunters. It aggregates intelligence from six major security APIs to provide a comprehensive risk assessment for IPs, URLs, and Files.

It supports single-target analysis, batch processing via file lists, and directory scanning, with automated reporting in CSV and JSON formats.

## **🚀 Features**

* **Multi-Source Intelligence:** Cross-references targets against multiple databases simultaneously.  
* **Risk Assessment Engine:** Aggregates data to calculate a unified **Confidence Score (0-100)** and **Verdict** (Clean, Suspicious, High Risk, Malicious).  
* **Batch Processing:**  
  * Bulk scan IPs or URLs from text files.  
  * Recursively scan local directories for file reputation.  
  * Built-in rate limiting to respect API quotas.  
* **Reporting:**  
  * **CSV:** Spreadsheet-friendly summary of all scanned items.  
  * **JSON:** Full detailed report including raw API responses.

## **🛡️ Integrations**

| Target Type | Source APIs Used |
| :---- | :---- |
| **IP Address** | VirusTotal v3, AbuseIPDB |
| **URL** | VirusTotal v3, urlscan.io, URLhaus |
| **File / Hash** | VirusTotal v3, MalwareBazaar, Hybrid Analysis, URLhaus |

## **📋 Prerequisites**

* Python 3.6+  
* requests library

## **⚙️ Installation**

1. **Clone the repository:**  
   git clone \[https://github.com/jharp21/sentientcheck.git\](https://github.com/jharp21/sentientcheck.git)  
   cd sentientcheck

2. **Install dependencies:**  
   pip install requests

## **🔑 Configuration (API Keys)**

You can provide API keys via **Environment Variables** (recommended) or enter them interactively when the script runs.

### **Environment Variables Setup**

Setting these allows the script to run without prompting for credentials every time.

**Linux / Mac:**

export VT\_API\_KEY="your\_virustotal\_key"  
export ABUSE\_API\_KEY="your\_abuseipdb\_key"  
export URLSCAN\_API\_KEY="your\_urlscan\_key"  
export HYBRID\_API\_KEY="your\_hybrid\_analysis\_key"  
export URLHAUS\_API\_KEY="your\_urlhaus\_key"

**Windows (PowerShell):**

$env:VT\_API\_KEY="your\_virustotal\_key"  
$env:ABUSE\_API\_KEY="your\_abuseipdb\_key"  
$env:URLSCAN\_API\_KEY="your\_urlscan\_key"  
$env:HYBRID\_API\_KEY="your\_hybrid\_analysis\_key"  
$env:URLHAUS\_API\_KEY="your\_urlhaus\_key"

**Note:** VirusTotal is the only *mandatory* API key. Others are optional but highly recommended for better accuracy.

## **💻 Usage**

Run the script:

python reputation\_checker.py

### **Modes**

1. **Check IP Address(es):** Enter a single IP (e.g., 1.1.1.1) or a path to a text file containing one IP per line.  
2. **Check URL(s):** Enter a single URL (e.g., http://example.com) or a path to a text file containing URLs.  
3. **Check File(s):** Enter a file path for a single hash check, or a **directory path** to hash and check every file in that folder.

### **Batch Scanning**

To scan multiple targets, create a text file (e.g., suspects.txt):

192.168.1.50  
10.0.0.5  
8.8.8.8

Then select Option 1 and provide the path: suspects.txt.

## **📊 Output Examples**

**Console Output:**

\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#  
   FINAL REPORT: \[http://malicious-site.example\](http://malicious-site.example)  
\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#\#  
Target Type:     URL  
Sources Checked: 3  
\------------------------------------------------------------  
GENERAL RATING:  \[\!\!\!\] MALICIOUS  
CONFIDENCE:      100/100  
\------------------------------------------------------------  
Risk Factors:  
 \- VirusTotal: 18 engines flagged this URL  
 \- urlscan.io: Verdict is MALICIOUS  
 \- URLhaus: URL is listed in database as malware\_download

## **📝 License**

[MIT](https://choosealicense.com/licenses/mit/)

## **⚠️ Disclaimer**

This tool is for educational and professional defensive security purposes only. Ensure you have authorization before scanning files or URLs that may contain sensitive data, as hashes and URLs are submitted to third-party services.

