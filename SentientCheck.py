import requests
import hashlib
import os
import sys
import base64
import json
import time
import csv
from datetime import datetime

# ReputationChecker: A tool to check IP, URL, and File reputation
# Integrations:
# 1. VirusTotal API v3 (IP, URL, File)
# 2. AbuseIPDB API v2 (IP Address)
# 3. urlscan.io API v1 (URL Search)
# 4. MalwareBazaar (File Hash)
# 5. Hybrid Analysis (File Hash)
# 6. URLhaus (URL and File Hash)

class ReputationChecker:
    def __init__(self, vt_api_key, abuse_api_key=None, urlscan_api_key=None, hybrid_api_key=None, urlhaus_api_key=None):
        self.vt_api_key = vt_api_key
        self.abuse_api_key = abuse_api_key
        self.urlscan_api_key = urlscan_api_key
        self.hybrid_api_key = hybrid_api_key
        self.urlhaus_api_key = urlhaus_api_key
        
        self.vt_base_url = "https://www.virustotal.com/api/v3"
        self.abuse_base_url = "https://api.abuseipdb.com/api/v2"
        self.urlscan_base_url = "https://urlscan.io/api/v1"
        self.mb_base_url = "https://mb-api.abuse.ch/api/v1/"
        self.hybrid_base_url = "https://www.hybrid-analysis.com/api/v2"
        self.urlhaus_base_url = "https://urlhaus-api.abuse.ch/v1"
        
        self.vt_headers = {
            "x-apikey": self.vt_api_key
        }
        
        if self.abuse_api_key:
            self.abuse_headers = {
                "Key": self.abuse_api_key,
                "Accept": "application/json"
            }

        if self.urlscan_api_key:
            self.urlscan_headers = {
                "API-Key": self.urlscan_api_key,
                "Content-Type": "application/json"
            }
            
        if self.hybrid_api_key:
            self.hybrid_headers = {
                "api-key": self.hybrid_api_key,
                "User-Agent": "Falcon Sandbox"
            }
            
        self.urlhaus_headers = {}
        if self.urlhaus_api_key:
            self.urlhaus_headers = {
                "Auth-Key": self.urlhaus_api_key
            }

    # --- VirusTotal Methods ---
    def check_ip_vt(self, ip_address):
        """Checks the reputation of an IP address using VirusTotal."""
        print(f"[*] (VirusTotal) Checking IP: {ip_address}...")
        endpoint = f"{self.vt_base_url}/ip_addresses/{ip_address}"
        try:
            response = requests.get(endpoint, headers=self.vt_headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "IP not found in VirusTotal database."}
            else:
                return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_url_vt(self, url):
        """Checks the reputation of a URL using VirusTotal."""
        print(f"[*] (VirusTotal) Checking URL: {url}...")
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.vt_base_url}/urls/{url_id}"
        
        try:
            response = requests.get(endpoint, headers=self.vt_headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "URL not previously analyzed. Submission required."}
            else:
                return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_vt(self, file_hash):
        """Checks file reputation using VirusTotal."""
        print(f"[*] (VirusTotal) Checking Hash: {file_hash}")
        endpoint = f"{self.vt_base_url}/files/{file_hash}"
        try:
            response = requests.get(endpoint, headers=self.vt_headers)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "File hash not found in VirusTotal database."}
            else:
                return {"error": f"VT API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- AbuseIPDB Methods ---
    def check_ip_abuse(self, ip_address):
        """Checks the reputation of an IP address using AbuseIPDB."""
        if not self.abuse_api_key:
            return None

        print(f"[*] (AbuseIPDB) Checking IP: {ip_address}...")
        endpoint = f"{self.abuse_base_url}/check"
        params = {
            'ipAddress': ip_address,
            'maxAgeInDays': '90',
            'verbose': ''
        }
        try:
            response = requests.get(endpoint, headers=self.abuse_headers, params=params)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 401:
                return {"error": "AbuseIPDB: Invalid API Key"}
            elif response.status_code == 429:
                return {"error": "AbuseIPDB: Rate Limit Exceeded"}
            else:
                return {"error": f"AbuseIPDB Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- urlscan.io Methods ---
    def check_url_urlscan(self, url):
        """Searches urlscan.io for existing scans of the URL."""
        if not self.urlscan_api_key:
            return None

        print(f"[*] (urlscan.io) Searching for existing scans: {url}...")
        endpoint = f"{self.urlscan_base_url}/search/"
        params = {
            'q': f'page.url:"{url}"',
            'size': 1
        }
        
        try:
            response = requests.get(endpoint, headers=self.urlscan_headers, params=params)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "No results found on urlscan.io."}
            else:
                return {"error": f"urlscan.io API Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- MalwareBazaar Methods ---
    def check_file_mb(self, file_hash):
        """Checks MalwareBazaar for the file hash (No API Key Required)."""
        print(f"[*] (MalwareBazaar) Checking Hash...")
        data = {'query': 'get_info', 'hash': file_hash}
        try:
            response = requests.post(self.mb_base_url, data=data, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"MalwareBazaar Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- Hybrid Analysis Methods ---
    def check_file_hybrid(self, file_hash):
        """Searches Hybrid Analysis for existing reports."""
        if not self.hybrid_api_key:
            return None
            
        print(f"[*] (Hybrid Analysis) Searching for reports...")
        endpoint = f"{self.hybrid_base_url}/search/hash"
        data = {'hash': file_hash}
        try:
            response = requests.post(endpoint, headers=self.hybrid_headers, data=data)
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {"error": "No existing report found."}
            else:
                return {"error": f"Hybrid Analysis Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- URLhaus Methods ---
    def check_url_urlhaus(self, url):
        """Checks a URL against the URLhaus database."""
        print(f"[*] (URLhaus) Checking URL...")
        endpoint = f"{self.urlhaus_base_url}/url/"
        data = {'url': url}
        try:
            # Include headers for authentication if key is provided
            response = requests.post(endpoint, data=data, headers=self.urlhaus_headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"URLhaus Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    def check_file_urlhaus(self, file_hash):
        """Checks a file hash against the URLhaus database."""
        print(f"[*] (URLhaus) Checking Hash...")
        endpoint = f"{self.urlhaus_base_url}/payload/"
        data = {'sha256_hash': file_hash}
        try:
            # Include headers for authentication if key is provided
            response = requests.post(endpoint, data=data, headers=self.urlhaus_headers, timeout=10)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"URLhaus Error: {response.status_code}"}
        except Exception as e:
            return {"error": str(e)}

    # --- Utilities ---
    def calculate_hash(self, filepath):
        sha256 = hashlib.sha256()
        try:
            with open(filepath, 'rb') as f:
                while True:
                    data = f.read(65536)
                    if not data: break
                    sha256.update(data)
            return sha256.hexdigest()
        except Exception as e:
            print(f"[!] Error reading file: {e}")
            return None

    # --- Risk Assessment & Reporting ---
    def assess_risk(self, target_type, results):
        """Aggregates results from various sources to calculate a general rating and confidence score."""
        score = 0
        factors = []
        sources_checked = 0

        # Helper to check if VT response is valid (checked successfully)
        def is_vt_checked(res):
            if not res: return False
            if 'data' in res: return True
            if 'error' in res and ("not found" in res['error'] or "not previously analyzed" in res['error']): return True
            return False

        # Helper for urlscan
        def is_urlscan_checked(res):
            if not res: return False
            if 'results' in res: return True
            if 'error' in res and "No results found" in res['error']: return True
            return False

        # Helper for Hybrid Analysis
        def is_hybrid_checked(res):
            if isinstance(res, list): return True
            if isinstance(res, dict) and 'error' in res and "No existing report" in res['error']: return True
            return False
            
        # Helper for URLhaus
        def is_urlhaus_checked(res):
            if not res: return False
            if "query_status" in res: return True # Covers 'ok' and 'no_results'
            return False

        # --- IP Logic ---
        if target_type == 'ip':
            vt = results.get('vt', {})
            if is_vt_checked(vt):
                sources_checked += 1
                if 'data' in vt:
                    stats = vt['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(f"VirusTotal: {malicious} engines flagged this IP")
            
            abuse = results.get('abuse', {})
            if (abuse and 'data' in abuse) or (abuse and 'error' in abuse and 'not found' in abuse['error']):
                sources_checked += 1
                if 'data' in abuse:
                    conf_score = abuse['data'].get('abuseConfidenceScore', 0)
                    if conf_score > 0:
                        score = max(score, conf_score)
                        factors.append(f"AbuseIPDB: Confidence score is {conf_score}%")

        # --- URL Logic ---
        elif target_type == 'url':
            vt = results.get('vt', {})
            if is_vt_checked(vt):
                sources_checked += 1
                if 'data' in vt:
                    stats = vt['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(f"VirusTotal: {malicious} engines flagged this URL")

            scan = results.get('urlscan', {})
            if is_urlscan_checked(scan):
                sources_checked += 1
                if 'results' in scan and len(scan['results']) > 0:
                    verdict = scan['results'][0].get('verdicts', {}).get('overall', {})
                    if verdict.get('malicious'):
                        score = 100
                        factors.append("urlscan.io: Verdict is MALICIOUS")

            haus = results.get('urlhaus', {})
            if is_urlhaus_checked(haus):
                sources_checked += 1
                if haus.get('query_status') == 'ok':
                    if haus.get('url_status') == 'online':
                        score = 100
                        factors.append(f"URLhaus: URL is currently ONLINE and listed as {haus.get('threat')}")
                    else:
                        score = max(score, 70)
                        factors.append(f"URLhaus: URL is listed in database as {haus.get('threat')}")

        # --- File Logic ---
        elif target_type == 'file':
            vt = results.get('vt', {})
            if is_vt_checked(vt):
                sources_checked += 1
                if 'data' in vt:
                    stats = vt['data']['attributes']['last_analysis_stats']
                    malicious = stats.get('malicious', 0)
                    if malicious > 0:
                        score = max(score, min(malicious * 10, 100))
                        factors.append(f"VirusTotal: {malicious} engines flagged this file")

            mb = results.get('mb', {})
            if mb:
                if mb.get('query_status') in ['ok', 'hash_not_found']:
                    sources_checked += 1
                if mb.get('query_status') == 'ok':
                    score = 100
                    factors.append("MalwareBazaar: Sample found in database")

            ha = results.get('hybrid', {})
            if is_hybrid_checked(ha):
                sources_checked += 1
                if isinstance(ha, list) and len(ha) > 0:
                    threat_score = ha[0].get('threat_score', 0)
                    if threat_score:
                        score = max(score, threat_score)
                        factors.append(f"Hybrid Analysis: Threat score {threat_score}/100")

            haus = results.get('urlhaus', {})
            if is_urlhaus_checked(haus):
                sources_checked += 1
                if haus.get('query_status') == 'ok':
                    score = 100
                    factors.append(f"URLhaus: File hash associated with malware payload")

        # Determine Verdict
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
            "sources_checked": sources_checked
        }

    def print_summary_report(self, target, target_type, assessment):
        print("\n" + "#" * 60)
        print(f"   FINAL REPORT: {target}")
        print("#" * 60)
        print(f"Target Type:     {target_type.upper()}")
        print(f"Sources Checked: {assessment['sources_checked']}")
        print("-" * 60)
        
        rating = assessment['rating']
        if rating == "CLEAN":
            print(f"GENERAL RATING:  [OK] {rating}")
        elif rating == "MALICIOUS":
            print(f"GENERAL RATING:  [!!!] {rating}")
        else:
            print(f"GENERAL RATING:  [!] {rating}")
            
        print(f"CONFIDENCE:      {assessment['score']}/100")
        print("-" * 60)
        
        if assessment['factors']:
            print("Risk Factors:")
            for factor in assessment['factors']:
                print(f" - {factor}")
        elif rating == "CLEAN":
            print("No malicious indicators found across checked sources.")
            
        print("#" * 60 + "\n")

    def save_json_report(self, report_data_list):
        if not report_data_list: return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        if len(report_data_list) == 1:
            target = report_data_list[0]['target']
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
        if not report_data_list: return
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"scan_results_{timestamp}.csv"
        
        try:
            with open(filename, mode='w', newline='', encoding='utf-8') as file:
                writer = csv.writer(file)
                # Header
                writer.writerow([
                    "Target", "Type", "Rating", "Score", "Sources Checked", 
                    "Risk Factors", "VT Detections", "AbuseIPDB Confidence", 
                    "URLhaus Status", "Hybrid Threat Score"
                ])
                
                for entry in report_data_list:
                    target = entry['target']
                    t_type = entry['type']
                    assess = entry['assessment']
                    raw = entry['raw_results']
                    
                    # Extract specific metrics safely
                    vt_score = "N/A"
                    if 'vt' in raw and 'data' in raw['vt']:
                         stats = raw['vt']['data']['attributes']['last_analysis_stats']
                         vt_score = f"{stats.get('malicious',0)}/{sum(stats.values())}"
                    
                    abuse_score = "N/A"
                    if 'abuse' in raw and 'data' in raw['abuse']:
                        abuse_score = f"{raw['abuse']['data'].get('abuseConfidenceScore')}%"
                        
                    urlhaus_status = "N/A"
                    if 'urlhaus' in raw:
                        if raw['urlhaus'].get('query_status') == 'ok':
                            urlhaus_status = raw['urlhaus'].get('threat', 'Malicious')
                        elif raw['urlhaus'].get('query_status') == 'no_results':
                            urlhaus_status = "Clean"
                    
                    hybrid_score = "N/A"
                    if 'hybrid' in raw and isinstance(raw['hybrid'], list) and len(raw['hybrid']) > 0:
                        hybrid_score = str(raw['hybrid'][0].get('threat_score', 'N/A'))

                    writer.writerow([
                        target,
                        t_type,
                        assess['rating'],
                        assess['score'],
                        assess['sources_checked'],
                        "; ".join(assess['factors']),
                        vt_score,
                        abuse_score,
                        urlhaus_status,
                        hybrid_score
                    ])
                    
            print(f"[+] CSV report saved to: {filename}")
        except Exception as e:
            print(f"[!] Failed to save CSV report: {e}")

    # --- Parsers ---
    def parse_vt_report(self, data):
        if not data: return
        if "error" in data:
            print(f"[VT] {data['error']}")
            return
        try:
            stats = data['data']['attributes']['last_analysis_stats']
            malicious = stats['malicious']
            total = sum(stats.values())
            print(f"[VT] Detections: {malicious}/{total}")
        except: pass

    def parse_abuse_report(self, data):
        if not data: return
        if "error" in data:
            print(f"[AbuseIPDB] {data['error']}")
            return
        try:
            print(f"[AbuseIPDB] Confidence: {data['data']['abuseConfidenceScore']}%")
        except: pass

    def parse_urlscan_report(self, data):
        if not data: return
        if "error" in data:
            print(f"[urlscan.io] {data['error']}")
            return
        try:
            if not data.get('results'): 
                # Should not reach here usually if error handling is correct, but safe fallback
                print(f"[urlscan.io] No previous results.")
                return
            res = data['results'][0]
            print(f"[urlscan.io] Last Scan: {res['task']['time']}")
        except: pass

    def parse_mb_report(self, data):
        if not data: return
        if "error" in data:
            print(f"[MalwareBazaar] {data['error']}")
            return
        if data.get("query_status") == "ok":
            print(f"[MalwareBazaar] Found: {data['data'][0]['signature']}")
        else:
            print(f"[MalwareBazaar] {data.get('query_status')}")

    def parse_hybrid_report(self, data):
        if not data: return
        if isinstance(data, dict) and "error" in data:
            print(f"[Hybrid Analysis] {data['error']}")
            return
        if isinstance(data, list):
            if len(data) > 0:
                print(f"[Hybrid Analysis] Threat Score: {data[0].get('threat_score')}/100")
            else:
                print(f"[Hybrid Analysis] No existing report found.")

    def parse_urlhaus_report(self, data, is_file=False):
        if not data: return
        if "error" in data:
            print(f"[URLhaus] {data['error']}")
            return
            
        query_status = data.get("query_status")
        
        if query_status == "ok":
            if is_file:
                print(f"[URLhaus] Malware Found: {data.get('signature', 'Unknown')}")
            else:
                print(f"[URLhaus] Status: {data.get('url_status')} | Threat: {data.get('threat')}")
        elif query_status == "no_results":
            print("[URLhaus] Status: [OK] Not Found in Database")
        else:
            print(f"[URLhaus] {query_status}")

def main():
    print("-" * 60)
    print("   SentientCheck - Multi-Source Reputation Tool")
    print("-" * 60)
    
    # Get API Keys
    vt_key = os.environ.get('VT_API_KEY') or input("Enter VirusTotal API Key: ").strip()
    abuse_key = os.environ.get('ABUSE_API_KEY') or ""
    urlscan_key = os.environ.get('URLSCAN_API_KEY') or ""
    hybrid_key = os.environ.get('HYBRID_API_KEY') or ""
    urlhaus_key = os.environ.get('URLHAUS_API_KEY') or ""
    
    if not vt_key:
        print("[!] Error: VirusTotal API Key is required.")
        sys.exit()
        
    checker = ReputationChecker(vt_key, abuse_key, urlscan_key, hybrid_key, urlhaus_key)
    
    while True:
        print("\nOptions:")
        print("1. Check IP Address(es) (Single or File List)")
        print("2. Check URL(s) (Single or File List)")
        print("3. Check File(s) (Single File or Directory)")
        print("4. Exit")
        
        choice = input("\nSelect option (1-4): ").strip()
        
        if choice == '4':
            print("Exiting...")
            break

        targets = []
        t_type = ""
        
        if choice == '1':
            inp = input("Enter IP or path to file list: ").strip().strip("'").strip('"')
            t_type = 'ip'
            if os.path.isfile(inp):
                try:
                    with open(inp, 'r') as f:
                        targets = [line.strip() for line in f if line.strip()]
                    print(f"[*] Loaded {len(targets)} IPs from file.")
                except Exception as e:
                    print(f"[!] Error reading file: {e}")
                    continue
            else:
                targets = [inp]
                
        elif choice == '2':
            inp = input("Enter URL or path to file list: ").strip().strip("'").strip('"')
            t_type = 'url'
            if os.path.isfile(inp):
                try:
                    with open(inp, 'r') as f:
                        targets = [line.strip() for line in f if line.strip()]
                    print(f"[*] Loaded {len(targets)} URLs from file.")
                except Exception as e:
                    print(f"[!] Error reading file: {e}")
                    continue
            else:
                targets = [inp]

        elif choice == '3':
            inp = input("Enter file path or directory: ").strip().strip("'").strip('"')
            t_type = 'file'
            if os.path.isdir(inp):
                print(f"[*] Scanning directory: {inp}")
                targets = [os.path.join(inp, f) for f in os.listdir(inp) if os.path.isfile(os.path.join(inp, f))]
                print(f"[*] Found {len(targets)} files.")
            elif os.path.isfile(inp):
                targets = [inp]
            else:
                print("[!] Invalid path.")
                continue
        else:
            print("[!] Invalid selection")
            continue

        # Processing Loop
        collected_reports = []
        
        for i, target_item in enumerate(targets):
            current_target_name = target_item
            if t_type == 'file':
                current_target_name = os.path.basename(target_item)
            
            print(f"\n[{i+1}/{len(targets)}] Checking: {current_target_name}")
            results = {}
            
            # API Calls
            if t_type == 'ip':
                results['vt'] = checker.check_ip_vt(target_item)
                results['abuse'] = checker.check_ip_abuse(target_item)
            elif t_type == 'url':
                results['vt'] = checker.check_url_vt(target_item)
                results['urlscan'] = checker.check_url_urlscan(target_item)
                results['urlhaus'] = checker.check_url_urlhaus(target_item)
            elif t_type == 'file':
                f_hash = checker.calculate_hash(target_item)
                if f_hash:
                    results['vt'] = checker.check_file_vt(f_hash)
                    results['mb'] = checker.check_file_mb(f_hash)
                    results['hybrid'] = checker.check_file_hybrid(f_hash)
                    results['urlhaus'] = checker.check_file_urlhaus(f_hash)
                else:
                    print(f"[!] Could not calculate hash for {target_item}")
                    continue

            # Assess & Store
            assessment = checker.assess_risk(t_type, results)
            checker.print_summary_report(current_target_name, t_type, assessment)
            
            # Show details (optional, maybe skip for large batches?)
            if len(targets) == 1:
                print("--- Detail Summary ---")
                if 'vt' in results: checker.parse_vt_report(results['vt'])
                if 'abuse' in results: checker.parse_abuse_report(results['abuse'])
                if 'urlscan' in results: checker.parse_urlscan_report(results['urlscan'])
                if 'mb' in results: checker.parse_mb_report(results['mb'])
                if 'hybrid' in results: checker.parse_hybrid_report(results['hybrid'])
                if 'urlhaus' in results: checker.parse_urlhaus_report(results['urlhaus'], is_file=(t_type=='file'))
            
            collected_reports.append({
                "target": current_target_name,
                "type": t_type,
                "assessment": assessment,
                "raw_results": results
            })

            # Rate Limiting for batches > 1
            if len(targets) > 1 and i < len(targets) - 1:
                print("[*] Pausing 2s to respect API rate limits...")
                time.sleep(2)

        # Export Options
        if collected_reports:
            print("\n" + "="*30)
            if len(targets) > 1:
                print("   BATCH SCAN COMPLETE")
            else:
                print("   SCAN COMPLETE")
            print("="*30)
            
            # Auto-save logic? Or prompt?
            save_csv = input("Save results to CSV? (y/n): ").lower()
            if save_csv == 'y':
                checker.save_csv_report(collected_reports)
                
            save_json = input("Save full details to JSON? (y/n): ").lower()
            if save_json == 'y':
                checker.save_json_report(collected_reports)

if __name__ == "__main__":
    main()