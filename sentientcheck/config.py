import os
from pathlib import Path

from sentientcheck.core import ReputationChecker

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


def create_checker(load_dotenv_file=True):
    keys = load_api_keys(load_dotenv_file=load_dotenv_file)
    return ReputationChecker(
        keys["VT_API_KEY"],
        keys["ABUSE_API_KEY"],
        keys["URLSCAN_API_KEY"],
        keys["HYBRID_API_KEY"],
        keys["URLHAUS_API_KEY"],
    )
