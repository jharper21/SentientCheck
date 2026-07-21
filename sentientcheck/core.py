import base64
import csv
import hashlib
import json
from datetime import datetime

import requests


REQUEST_TIMEOUT = 10


class ReputationChecker:
    def __init__(
        self,
        vt_api_key,
        abuse_api_key=None,
        urlscan_api_key=None,
        hybrid_api_key=None,
        abusech_api_key=None,
        urlhaus_api_key=None,
    ):
        self.vt_api_key = vt_api_key
        self.abuse_api_key = abuse_api_key
        self.urlscan_api_key = urlscan_api_key
        self.hybrid_api_key = hybrid_api_key
        self.abusech_api_key = abusech_api_key or urlhaus_api_key
        self.urlhaus_api_key = self.abusech_api_key

        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.abuse_base_url = "https://api.abuseipdb.com/api/v2"
        self.urlscan_base_url = "https://urlscan.io/api/v1"
        self.mb_base_url = "https://mb-api.abuse.ch/api/v1/"
        self.hybrid_base_url = "https://www.hybrid-analysis.com/api/v2"
        self.urlhaus_base_url = "https://urlhaus-api.abuse.ch/v1"

        self.vt_headers = {"x-apikey": self.vt_api_key}

        if self.abuse_api_key:
            self.abuse_headers = {
                "Key": self.abuse_api_key,
                "Accept": "application/json",
            }

        if self.urlscan_api_key:
            self.urlscan_headers = {
                "API-Key": self.urlscan_api_key,
                "Content-Type": "application/json",
            }

        if self.hybrid_api_key:
            self.hybrid_headers = {
                "api-key": self.hybrid_api_key,
                "User-Agent": "Falcon Sandbox",
            }

        self.abusech_headers = {}
        if self.abusech_api_key:
            self.abusech_headers = {"Auth-Key": self.abusech_api_key}
        self.urlhaus_headers = self.abusech_headers

    def check_ip_vt(self, ip_address):
        """Checks the reputation of an IP address using VirusTotal."""
        print(f"[*] (VirusTotal) Checking IP: {ip_address}...")
        endpoint = f"{self.vt_base_url}/ip_addresses/{ip_address}"
        try:
            response = requests.get(
                endpoint,
                headers=self.vt_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {"error": "IP not found in VirusTotal database."}
            return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_url_vt(self, url):
        """Checks the reputation of a URL using VirusTotal."""
        print(f"[*] (VirusTotal) Checking URL: {url}...")
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.vt_base_url}/urls/{url_id}"

        try:
            response = requests.get(
                endpoint,
                headers=self.vt_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {"error": "URL not previously analyzed. Submission required."}
            return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_vt(self, file_hash):
        """Checks file reputation using VirusTotal."""
        print(f"[*] (VirusTotal) Checking Hash: {file_hash}")
        endpoint = f"{self.vt_base_url}/files/{file_hash}"
        try:
            response = requests.get(
                endpoint,
                headers=self.vt_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {"error": "File hash not found in VirusTotal database."}
            return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_ip_abuse(self, ip_address):
        """Checks the reputation of an IP address using AbuseIPDB."""
        if not self.abuse_api_key:
            return None

        print(f"[*] (AbuseIPDB) Checking IP: {ip_address}...")
        endpoint = f"{self.abuse_base_url}/check"
        params = {
            "ipAddress": ip_address,
            "maxAgeInDays": "90",
            "verbose": "",
        }
        try:
            response = requests.get(
                endpoint,
                headers=self.abuse_headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 401:
                return {"error": "AbuseIPDB: Invalid API Key"}
            if response.status_code == 429:
                return {"error": "AbuseIPDB: Rate Limit Exceeded"}
            return {"error": f"AbuseIPDB Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_url_urlscan(self, url):
        """Searches urlscan.io for existing scans of the URL."""
        if not self.urlscan_api_key:
            return None

        print(f"[*] (urlscan.io) Searching for existing scans: {url}...")
        endpoint = f"{self.urlscan_base_url}/search/"
        params = {
            "q": f'page.url:"{url}"',
            "size": 1,
        }

        try:
            response = requests.get(
                endpoint,
                headers=self.urlscan_headers,
                params=params,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {"error": "No results found on urlscan.io."}
            return {"error": f"urlscan.io API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_mb(self, file_hash):
        """Checks MalwareBazaar for the file hash."""
        if not self.abusech_api_key:
            return None

        print("[*] (MalwareBazaar) Checking Hash...")
        data = {"query": "get_info", "hash": file_hash}
        try:
            response = requests.post(
                self.mb_base_url,
                data=data,
                headers=self.abusech_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"MalwareBazaar Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_hybrid(self, file_hash):
        """Searches Hybrid Analysis for existing reports."""
        if not self.hybrid_api_key:
            return None

        print("[*] (Hybrid Analysis) Searching for reports...")
        endpoint = f"{self.hybrid_base_url}/search/hash"
        data = {"hash": file_hash}
        try:
            response = requests.post(
                endpoint,
                headers=self.hybrid_headers,
                data=data,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            if response.status_code == 404:
                return {"error": "No existing report found."}
            return {"error": f"Hybrid Analysis Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_url_urlhaus(self, url):
        """Checks a URL against the URLhaus database."""
        if not self.abusech_api_key:
            return None

        print("[*] (URLhaus) Checking URL...")
        endpoint = f"{self.urlhaus_base_url}/url/"
        data = {"url": url}
        try:
            response = requests.post(
                endpoint,
                data=data,
                headers=self.urlhaus_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"URLhaus Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_urlhaus(self, file_hash):
        """Checks a file hash against the URLhaus database."""
        if not self.abusech_api_key:
            return None

        print("[*] (URLhaus) Checking Hash...")
        endpoint = f"{self.urlhaus_base_url}/payload/"
        data = {"sha256_hash": file_hash}
        try:
            response = requests.post(
                endpoint,
                data=data,
                headers=self.urlhaus_headers,
                timeout=REQUEST_TIMEOUT,
            )
            if response.status_code == 200:
                return response.json()
            return {"error": f"URLhaus Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def calculate_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, "rb") as f:
                while True:
                    data = f.read(65536)
                    if not data:
                        break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return None

    def assess_risk(self, target_type, results):
        """Aggregates results from various sources into a rating and confidence score."""
        score = 0
        factors = []
        sources_checked = 0

        def is_vt_checked(res):
            if not res:
                return False
            if "data" in res:
                return True
            if "error" in res and (
                "not found" in res["error"]
                or "not previously analyzed" in res["error"]
            ):
                return True
            return False

        def is_urlscan_checked(res):
            if not res:
                return False
            if "results" in res:
                return True
            if "error" in res and "No results found" in res["error"]:
                return True
            return False

        def is_hybrid_checked(res):
            if isinstance(res, list):
                return True
            if (
                isinstance(res, dict)
                and "error" in res
                and "No existing report" in res["error"]
            ):
                return True
            return False

        def is_urlhaus_checked(res):
            if not res:
                return False
            return "query_status" in res

        if target_type == "ip":
            vt = results.get("vt", {})
            if is_vt_checked(vt):
                sources_checked += 1
                if "data" in vt:
                    stats = vt["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(
                            f"VirusTotal: {malicious} engines flagged this IP"
                        )

            abuse = results.get("abuse", {})
            if (abuse and "data" in abuse) or (
                abuse and "error" in abuse and "not found" in abuse["error"]
            ):
                sources_checked += 1
                if "data" in abuse:
                    conf_score = abuse["data"].get("abuseConfidenceScore", 0)
                    if conf_score > 0:
                        score = max(score, conf_score)
                        factors.append(
                            f"AbuseIPDB: Confidence score is {conf_score}%"
                        )

        elif target_type == "url":
            vt = results.get("vt", {})
            if is_vt_checked(vt):
                sources_checked += 1
                if "data" in vt:
                    stats = vt["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(
                            f"VirusTotal: {malicious} engines flagged this URL"
                        )

            scan = results.get("urlscan", {})
            if is_urlscan_checked(scan):
                sources_checked += 1
                if "results" in scan and len(scan["results"]) > 0:
                    verdict = scan["results"][0].get("verdicts", {}).get("overall", {})
                    if verdict.get("malicious"):
                        score = 100
                        factors.append("urlscan.io: Verdict is MALICIOUS")

            haus = results.get("urlhaus", {})
            if is_urlhaus_checked(haus):
                sources_checked += 1
                if haus.get("query_status") == "ok":
                    if haus.get("url_status") == "online":
                        score = 100
                        factors.append(
                            "URLhaus: URL is currently ONLINE and listed as "
                            f"{haus.get('threat')}"
                        )
                    else:
                        score = max(score, 70)
                        factors.append(
                            "URLhaus: URL is listed in database as "
                            f"{haus.get('threat')}"
                        )

        elif target_type == "file":
            vt = results.get("vt", {})
            if is_vt_checked(vt):
                sources_checked += 1
                if "data" in vt:
                    stats = vt["data"]["attributes"]["last_analysis_stats"]
                    malicious = stats.get("malicious", 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(
                            f"VirusTotal: {malicious} engines flagged this file"
                        )

            mb = results.get("mb", {})
            if mb:
                if mb.get("query_status") in ["ok", "hash_not_found"]:
                    sources_checked += 1
                if mb.get("query_status") == "ok":
                    score = 100
                    factors.append("MalwareBazaar: Sample found in database")

            ha = results.get("hybrid", {})
            if is_hybrid_checked(ha):
                sources_checked += 1
                if isinstance(ha, list) and len(ha) > 0:
                    threat_score = ha[0].get("threat_score", 0)
                    if threat_score:
                        score = max(score, threat_score)
                        factors.append(
                            f"Hybrid Analysis: Threat score {threat_score}/100"
                        )

            haus = results.get("urlhaus", {})
            if is_urlhaus_checked(haus):
                sources_checked += 1
                if haus.get("query_status") == "ok":
                    score = 100
                    factors.append("URLhaus: File hash associated with malware payload")

        if score == 0:
            rating = "CLEAN"
        elif score < 50:
            rating = "SUSPICIOUS"
        elif score < 80:
            rating = "HIGH RISK"
        else:
            rating = "MALICIOUS"

        return {
            "rating": rating,
            "score": score,
            "factors": factors,
            "sources_checked": sources_checked,
        }

    def print_summary_report(self, target, target_type, assessment):
        print("\n" + "#" * 60)
        print(f"   FINAL REPORT: {target}")
        print("#" * 60)
        print(f"Target Type:     {target_type.upper()}")
        print(f"Sources Checked: {assessment['sources_checked']}")
        print("-" * 60)

        rating = assessment["rating"]
        if rating == "CLEAN":
            print(f"GENERAL RATING:  [OK] {rating}")
        elif rating == "MALICIOUS":
            print(f"GENERAL RATING:  [!!!] {rating}")
        else:
            print(f"GENERAL RATING:  [!] {rating}")

        print(f"CONFIDENCE:      {assessment['score']}/100")
        print("-" * 60)

        if assessment["factors"]:
            print("Risk Factors:")
            for factor in assessment["factors"]:
                print(f" - {factor}")
        elif rating == "CLEAN":
            print("No malicious indicators found across checked sources.")

        print("#" * 60 + "\n")

    def save_json_report(self, report_data_list):
        if not report_data_list:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if len(report_data_list) == 1:
            target = report_data_list[0]["target"]
            safe_target = "".join([c if c.isalnum() else "_" for c in target])
            filename = f"report_{safe_target}_{timestamp}.json"
        else:
            filename = f"report_batch_{timestamp}.json"

        try:
            with open(filename, "w") as f:
                json.dump(report_data_list, f, indent=4)
            print(f"[+] Full JSON report saved to: {filename}")
        except Exception as e:
            print(f"[!] Failed to save JSON report: {e}")

    def save_csv_report(self, report_data_list):
        if not report_data_list:
            return

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"

        try:
            with open(filename, mode="w", newline="", encoding="utf-8") as file:
                writer = csv.writer(file)
                writer.writerow(
                    [
                        "Target",
                        "Type",
                        "Rating",
                        "Score",
                        "Sources Checked",
                        "Risk Factors",
                        "VT Detections",
                        "AbuseIPDB Confidence",
                        "URLhaus Status",
                        "Hybrid Threat Score",
                    ]
                )

                for entry in report_data_list:
                    target = entry["target"]
                    t_type = entry["type"]
                    assess = entry["assessment"]
                    raw = entry["raw_results"]

                    vt_score = "N/A"
                    if "vt" in raw and "data" in raw["vt"]:
                        stats = raw["vt"]["data"]["attributes"]["last_analysis_stats"]
                        vt_score = f"{stats.get('malicious', 0)}/{sum(stats.values())}"

                    abuse_score = "N/A"
                    if "abuse" in raw and "data" in raw["abuse"]:
                        abuse_score = (
                            f"{raw['abuse']['data'].get('abuseConfidenceScore')}%"
                        )

                    urlhaus_status = "N/A"
                    if "urlhaus" in raw:
                        if raw["urlhaus"].get("query_status") == "ok":
                            urlhaus_status = raw["urlhaus"].get("threat", "Malicious")
                        elif raw["urlhaus"].get("query_status") == "no_results":
                            urlhaus_status = "Clean"

                    hybrid_score = "N/A"
                    if (
                        "hybrid" in raw
                        and isinstance(raw["hybrid"], list)
                        and len(raw["hybrid"]) > 0
                    ):
                        hybrid_score = str(raw["hybrid"][0].get("threat_score", "N/A"))

                    writer.writerow(
                        [
                            target,
                            t_type,
                            assess["rating"],
                            assess["score"],
                            assess["sources_checked"],
                            "; ".join(assess["factors"]),
                            vt_score,
                            abuse_score,
                            urlhaus_status,
                            hybrid_score,
                        ]
                    )

            print(f"[+] CSV report saved to: {filename}")
        except Exception as e:
            print(f"[!] Failed to save CSV report: {e}")

    def parse_vt_report(self, data):
        if not data:
            return
        if "error" in data:
            print(f"[VT] {data['error']}")
            return
        try:
            stats = data["data"]["attributes"]["last_analysis_stats"]
            malicious = stats["malicious"]
            total = sum(stats.values())
            print(f"[VT] Detections: {malicious}/{total}")
        except Exception:
            pass

    def parse_abuse_report(self, data):
        if not data:
            return
        if "error" in data:
            print(f"[AbuseIPDB] {data['error']}")
            return
        try:
            print(f"[AbuseIPDB] Confidence: {data['data']['abuseConfidenceScore']}%")
        except Exception:
            pass

    def parse_urlscan_report(self, data):
        if not data:
            return
        if "error" in data:
            print(f"[urlscan.io] {data['error']}")
            return
        try:
            if not data.get("results"):
                print("[urlscan.io] No previous results.")
                return
            res = data["results"][0]
            print(f"[urlscan.io] Last Scan: {res['task']['time']}")
        except Exception:
            pass

    def parse_mb_report(self, data):
        if not data:
            return
        if "error" in data:
            print(f"[MalwareBazaar] {data['error']}")
            return
        if data.get("query_status") == "ok":
            print(f"[MalwareBazaar] Found: {data['data'][0]['signature']}")
        else:
            print(f"[MalwareBazaar] {data.get('query_status')}")

    def parse_hybrid_report(self, data):
        if not data:
            return
        if isinstance(data, dict) and "error" in data:
            print(f"[Hybrid Analysis] {data['error']}")
            return
        if isinstance(data, list):
            if len(data) > 0:
                print(f"[Hybrid Analysis] Threat Score: {data[0].get('threat_score')}/100")
            else:
                print("[Hybrid Analysis] No existing report found.")

    def parse_urlhaus_report(self, data, is_file=False):
        if not data:
            return
        if "error" in data:
            print(f"[URLhaus] {data['error']}")
            return

        query_status = data.get("query_status")

        if query_status == "ok":
            if is_file:
                print(f"[URLhaus] Malware Found: {data.get('signature', 'Unknown')}")
            else:
                print(
                    "[URLhaus] Status: "
                    f"{data.get('url_status')} | Threat: {data.get('threat')}"
                )
        elif query_status == "no_results":
            print("[URLhaus] Status: [OK] Not Found in Database")
        else:
            print(f"[URLhaus] {query_status}")
