from pathlib import Path

import requests

from sentientcheck.config import API_KEY_ENV_VARS, PROVIDERS, load_api_keys, project_root
from sentientcheck.core import REQUEST_TIMEOUT


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
                timeout=REQUEST_TIMEOUT,
            )
            return status_from_response(response)

        if slug == "abuseipdb":
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers={"Key": key, "Accept": "application/json"},
                params={"ipAddress": "127.0.0.1", "maxAgeInDays": "90"},
                timeout=REQUEST_TIMEOUT,
            )
            return status_from_response(response)

        if slug == "urlscan":
            response = requests.get(
                "https://urlscan.io/user/quotas/",
                headers={"API-Key": key},
                timeout=REQUEST_TIMEOUT,
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


def write_env_file(keys, path=None, overwrite=True):
    output_path = Path(path) if path else project_root() / ".env"
    if output_path.exists() and not overwrite:
        raise FileExistsError(f"Refusing to overwrite existing env file: {output_path}")
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

    print("\nNext: configure your MCP client to run `python sentientcheck_mcp.py`.")


if __name__ == "__main__":
    main()
