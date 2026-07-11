import csv
import json
from datetime import datetime
from pathlib import Path


def save_json_report(report_data_list, output_path=None, overwrite=False):
    output = Path(output_path) if output_path is not None else _default_json_path(report_data_list)
    _ensure_can_write(output, overwrite)
    with output.open("w", encoding="utf-8") as report_file:
        json.dump(report_data_list, report_file, indent=4)
    return output


def save_csv_report(report_data_list, output_path=None, overwrite=False):
    output = Path(output_path) if output_path is not None else _default_csv_path()
    _ensure_can_write(output, overwrite)
    with output.open(mode="w", newline="", encoding="utf-8") as report_file:
        writer = csv.writer(report_file)
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
            assessment = entry["assessment"]
            raw = entry["raw_results"]
            writer.writerow(
                [
                    entry["target"],
                    entry["type"],
                    assessment["rating"],
                    assessment["score"],
                    assessment["sources_checked"],
                    "; ".join(assessment["factors"]),
                    _vt_detections(raw),
                    _abuse_confidence(raw),
                    _urlhaus_status(raw),
                    _hybrid_threat_score(raw),
                ]
            )

    return output


def _ensure_can_write(output, overwrite):
    if output.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing report: {output}")


def _default_json_path(report_data_list):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if len(report_data_list) == 1:
        target = report_data_list[0]["target"]
        safe_target = "".join(c if c.isalnum() else "_" for c in target)
        return Path(f"report_{safe_target}_{timestamp}.json")
    return Path(f"report_batch_{timestamp}.json")


def _default_csv_path():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Path(f"scan_results_{timestamp}.csv")


def _vt_detections(raw):
    vt = raw.get("vt")
    if isinstance(vt, dict) and "data" in vt:
        stats = vt["data"]["attributes"]["last_analysis_stats"]
        return f"{stats.get('malicious', 0)}/{sum(stats.values())}"
    return "N/A"


def _abuse_confidence(raw):
    abuse = raw.get("abuse")
    if isinstance(abuse, dict) and "data" in abuse:
        return f"{abuse['data'].get('abuseConfidenceScore')}%"
    return "N/A"


def _urlhaus_status(raw):
    urlhaus = raw.get("urlhaus")
    if not isinstance(urlhaus, dict):
        return "N/A"
    if urlhaus.get("query_status") == "ok":
        return urlhaus.get("threat", "Malicious")
    if urlhaus.get("query_status") == "no_results":
        return "Clean"
    return "N/A"


def _hybrid_threat_score(raw):
    hybrid = raw.get("hybrid")
    if isinstance(hybrid, list) and len(hybrid) > 0:
        return str(hybrid[0].get("threat_score", "N/A"))
    return "N/A"
