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
        raise ValueError(f"Could not calculate hash for {file_path}")
    report = check_file_hash(checker, file_hash)
    report["target"] = file_path.name
    report["path"] = str(file_path)
    report["sha256"] = file_hash
    return report


def scan_targets(checker, target_type, targets, sleep_seconds=2):
    target_list = load_targets(targets)
    reports = []

    for index, target in enumerate(target_list):
        if target_type == "ip":
            report = check_ip(checker, target)
        elif target_type == "url":
            report = check_url(checker, target)
        elif target_type == "file":
            report = check_file_hash(checker, target)
        else:
            raise ValueError(f"Unsupported target type: {target_type}")

        reports.append(report)
        if sleep_seconds and index < len(target_list) - 1:
            time.sleep(sleep_seconds)

    return reports


def load_targets(path_or_targets):
    if isinstance(path_or_targets, (list, tuple, set)):
        return [str(target) for target in path_or_targets]

    path = Path(path_or_targets)
    if path.is_file():
        return [
            line.strip()
            for line in path.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]

    return [str(path_or_targets)]


def scan_directory(checker, path, sleep_seconds=2):
    directory = Path(path)
    if not directory.is_dir():
        raise ValueError(f"Invalid directory: {directory}")

    files = [entry for entry in directory.iterdir() if entry.is_file()]
    reports = []
    for index, file_path in enumerate(files):
        reports.append(check_file_path(checker, file_path))
        if sleep_seconds and index < len(files) - 1:
            time.sleep(sleep_seconds)

    return reports


def build_report(checker, target, target_type, results):
    return {
        "target": target,
        "type": target_type,
        "assessment": checker.assess_risk(target_type, results),
        "raw_results": results,
    }
