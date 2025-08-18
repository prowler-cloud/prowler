#!/usr/bin/env python3
"""
Bulk-provision cloud providers in Prowler Cloud/App via REST API.

- Supports providers: aws, azure, gcp, kubernetes, m365, github
- Reads YAML / JSON / CSV input listing provider entries
- Builds provider-specific payloads
- POSTs to the providers endpoint with concurrency and retries
- Optionally supports a "raw" passthrough mode for future/advanced payloads:
  Each item may specify: {"endpoint": "/custom/path", "payload": {...}} to send as-is.

Environment:
  PROWLER_API_BASE   (default: https://api.prowler.com/api/v1)
  PROWLER_API_TOKEN  (required unless --token is provided)

Usage:
  python bulk_provision_prowler.py providers.yaml \
    --base-url https://api.prowler.com/api/v1 \
    --providers-endpoint /providers \
    --concurrency 6

Notes:
  * Check your Prowler API docs at /api/v1/docs for the exact fields accepted by your version.
  * For self-hosted Prowler App, base URL is typically http://localhost:8080/api/v1

Author: Prowler Contributors ✨
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

# ----------------------------- CLI / I/O utils ----------------------------- #


def load_items(path: Path) -> List[Dict[str, Any]]:
    """Load provider items from YAML, JSON, or CSV file."""
    ext = path.suffix.lower()
    if ext in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore
        except Exception:
            sys.exit("PyYAML is required for YAML inputs. pip install pyyaml")
        with path.open("r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
        if isinstance(data, dict):
            # allow single object with "items" key
            data = data.get("items") or []
        if not isinstance(data, list):
            sys.exit("YAML root must be a list (or dict with 'items').")
        return data

    if ext == ".json":
        with path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("items") or []
        if not isinstance(data, list):
            sys.exit("JSON root must be a list (or dict with 'items').")
        return data

    if ext == ".csv":
        items: List[Dict[str, Any]] = []
        with path.open("r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # Support a 'credentials' column containing JSON
                creds = row.get("credentials")
                if creds:
                    try:
                        row["credentials"] = json.loads(creds)
                    except Exception as e:
                        sys.exit(f"Invalid JSON in 'credentials' column: {e}")
                # Normalize empty strings to None
                for k, v in list(row.items()):
                    if isinstance(v, str) and v.strip() == "":
                        row[k] = None
                items.append(row)
        return items

    sys.exit(f"Unsupported input file type: {ext}")


def env_or_arg(token_arg: Optional[str]) -> str:
    """Get API token from argument or environment variable."""
    token = token_arg or os.getenv("PROWLER_API_TOKEN")
    if not token:
        sys.exit("Missing API token. Set --token or PROWLER_API_TOKEN.")
    return token


def normalize_base_url(url: str) -> str:
    """Normalize base URL format."""
    url = url.rstrip("/")
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


# ----------------------------- Payload builders ---------------------------- #


def read_text_file(path: Optional[str]) -> Optional[str]:
    """Read text content from file path."""
    if not path:
        return None
    p = Path(os.path.expanduser(path))
    return p.read_text(encoding="utf-8")


def build_payload(item: Dict[str, Any]) -> Tuple[str, Dict[str, Any]]:
    """
    Returns (endpoint_path, payload) to POST.

    If the item includes 'endpoint' and 'payload', passthrough these directly.

    Otherwise, build a standardized payload for POST /providers (default).
    """
    # Passthrough mode for advanced users / future endpoints
    if "endpoint" in item and "payload" in item:
        return str(item["endpoint"]), dict(item["payload"])

    provider = str(item.get("provider", "")).strip().lower()
    uid = item.get("uid")  # account id / subscription id / project id / etc.
    alias = item.get("alias")
    auth_method = str(item.get("auth_method", "")).strip().lower()
    creds: Dict[str, Any] = item.get("credentials") or {}

    if not provider or not uid:
        raise ValueError("Each item must include 'provider' and 'uid'.")

    # Provider-specific credential mapping based on actual API schema
    credentials_payload: Dict[str, Any] = {}

    if provider == "aws":
        if auth_method == "role":
            credentials_payload.update(
                {
                    "role_arn": creds.get("role_arn"),
                    "external_id": creds.get("external_id"),
                    "role_session_name": creds.get("session_name"),
                    "session_duration": creds.get("duration_seconds", 3600),
                    # Optional: keys used to assume the role
                    "aws_access_key_id": creds.get("access_key_id"),
                    "aws_secret_access_key": creds.get("secret_access_key"),
                    "aws_session_token": creds.get("session_token"),
                }
            )
        elif auth_method == "credentials":
            credentials_payload.update(
                {
                    "aws_access_key_id": creds.get("access_key_id"),
                    "aws_secret_access_key": creds.get("secret_access_key"),
                    "aws_session_token": creds.get("session_token"),
                }
            )
        else:
            raise ValueError("AWS 'auth_method' must be 'role' or 'credentials'.")

    elif provider == "azure":
        if auth_method != "service_principal":
            raise ValueError("Azure 'auth_method' must be 'service_principal'.")
        credentials_payload.update(
            {
                "tenant_id": creds.get("tenant_id"),
                "client_id": creds.get("client_id"),
                "client_secret": creds.get("client_secret"),
            }
        )

    elif provider == "gcp":
        if auth_method == "service_account_json":
            inline = creds.get("inline_json")
            path = creds.get("service_account_key_json_path")
            if path and not inline:
                inline_content = read_text_file(path)
                if inline_content:
                    try:
                        import json

                        inline = json.loads(inline_content)
                    except json.JSONDecodeError:
                        raise ValueError(
                            f"Invalid JSON in service account key file: {path}"
                        )
            elif inline and isinstance(inline, str):
                try:
                    import json

                    inline = json.loads(inline)
                except json.JSONDecodeError:
                    raise ValueError("Invalid JSON in inline_json credential")
            credentials_payload.update({"service_account_key": inline})
        elif auth_method == "adc":
            # Application Default Credentials
            credentials_payload.update(
                {
                    "client_id": creds.get("client_id"),
                    "client_secret": creds.get("client_secret"),
                    "refresh_token": creds.get("refresh_token"),
                }
            )
        else:
            raise ValueError(
                "GCP 'auth_method' must be 'service_account_json' or 'adc'."
            )

    elif provider == "kubernetes":
        if auth_method != "kubeconfig":
            raise ValueError("Kubernetes 'auth_method' must be 'kubeconfig'.")
        inline = creds.get("kubeconfig_inline")
        path = creds.get("kubeconfig_path")
        if path and not inline:
            inline = read_text_file(path)
        credentials_payload.update({"kubeconfig_content": inline})

    elif provider == "m365":
        if auth_method != "service_principal":
            raise ValueError("M365 'auth_method' must be 'service_principal'.")
        credentials_payload.update(
            {
                "tenant_id": creds.get("tenant_id"),
                "client_id": creds.get("client_id"),
                "client_secret": creds.get("client_secret"),
                "user": creds.get("username"),
                "password": creds.get("password"),
            }
        )

    elif provider == "github":
        if auth_method == "personal_access_token":
            credentials_payload.update({"personal_access_token": creds.get("token")})
        elif auth_method == "oauth_app_token":
            credentials_payload.update({"oauth_app_token": creds.get("oauth_token")})
        elif auth_method == "github_app":
            # Accept inline PK or path
            pk = creds.get("private_key_inline")
            if not pk and creds.get("private_key_path"):
                pk = read_text_file(creds.get("private_key_path"))
            credentials_payload.update(
                {"github_app_id": int(creds.get("app_id", 0)), "github_app_key": pk}
            )
        else:
            raise ValueError(
                "GitHub 'auth_method' must be personal_access_token | oauth_app_token | github_app."
            )

    else:
        raise ValueError(f"Unsupported provider: {provider}")

    # Standardized provider creation payload for POST /providers
    # The credentials are sent as direct attributes, not under 'secret'
    attributes = {
        "provider": provider,
        "uid": uid,
        "alias": alias,
    }
    
    # Add credentials directly to attributes
    attributes.update(credentials_payload)
    
    payload: Dict[str, Any] = {
        "data": {
            "type": "providers",
            "attributes": attributes,
        }
    }

    # Return default endpoint
    return "/providers", payload


# ----------------------------- HTTP client --------------------------------- #


@dataclass
class ApiClient:
    """HTTP client for Prowler API."""

    base_url: str
    token: str
    verify_ssl: bool = True
    timeout: int = 60

    def _headers(self) -> Dict[str, str]:
        """Generate HTTP headers for API requests."""
        return {
            "Authorization": f"Bearer {self.token}",
            "Content-Type": "application/vnd.api+json",
            "Accept": "application/vnd.api+json",
        }

    def post(self, path: str, json_body: Dict[str, Any]) -> requests.Response:
        """Make POST request to API endpoint."""
        url = f"{self.base_url}{path}"
        return requests.post(
            url,
            headers=self._headers(),
            json=json_body,
            timeout=self.timeout,
            verify=self.verify_ssl,
        )


def with_retries(
    func, *, retries=4, base_delay=1.25, exceptions=(requests.RequestException,)
):
    """Decorator to add retry logic to HTTP requests."""

    def wrapper(*args, **kwargs):
        for attempt in range(retries + 1):
            try:
                return func(*args, **kwargs)
            except exceptions:
                if attempt >= retries:
                    raise
                sleep = base_delay * (2**attempt)
                time.sleep(sleep)
        # Shouldn't reach here
        return func(*args, **kwargs)

    return wrapper


@with_retries
def create_one(
    client: ApiClient, endpoint: str, payload: Dict[str, Any]
) -> Tuple[bool, Dict[str, Any]]:
    """Create a single provider with retry logic."""
    resp = client.post(endpoint, payload)
    try:
        data = resp.json()
    except ValueError:
        data = {"text": resp.text}
    if 200 <= resp.status_code < 300:
        return True, data
    else:
        return False, {"status": resp.status_code, "body": data}


# ----------------------------- main ---------------------------------------- #


def main():
    """Main function to process bulk provider provisioning."""
    parser = argparse.ArgumentParser(description="Bulk provision providers in Prowler.")
    parser.add_argument("input_file", help="YAML/JSON/CSV file with provider entries.")
    parser.add_argument(
        "--base-url",
        default=os.getenv("PROWLER_API_BASE", "https://api.prowler.com/api/v1"),
        help="API base URL (default: env PROWLER_API_BASE or Prowler Cloud SaaS).",
    )
    parser.add_argument(
        "--token", default=None, help="Bearer token (default: PROWLER_API_TOKEN)."
    )
    parser.add_argument(
        "--providers-endpoint",
        default="/providers",
        help="Path to the providers create endpoint (default: /providers).",
    )
    parser.add_argument(
        "--concurrency", type=int, default=5, help="Number of concurrent requests."
    )
    parser.add_argument(
        "--timeout", type=int, default=60, help="Per-request timeout (seconds)."
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (not recommended).",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be sent without calling the API.",
    )
    args = parser.parse_args()

    token = env_or_arg(args.token)
    base_url = normalize_base_url(args.base_url)

    items = load_items(Path(args.input_file))
    if not items:
        print("No items found in input file.")
        return

    client = ApiClient(
        base_url=base_url,
        token=token,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
    )

    requests_to_send: List[Tuple[int, str, Dict[str, Any]]] = []
    for idx, item in enumerate(items, start=1):
        try:
            endpoint, payload = build_payload(item)
        except Exception as e:
            print(f"[{idx}] ❌ Skipping item due to build error: {e}")
            continue

        # Allow overriding endpoint path globally (for standard creation)
        if endpoint == "/providers":
            endpoint = args.providers_endpoint

        if args.dry_run:
            print(
                f"[{idx}] DRY-RUN → POST {base_url}{endpoint}\n{json.dumps(payload, indent=2)}\n"
            )
        else:
            requests_to_send.append((idx, endpoint, payload))

    if args.dry_run or not requests_to_send:
        if not requests_to_send:
            print("Nothing to send.")
        return

    successes, failures = 0, 0
    results: List[Tuple[int, bool, Dict[str, Any]]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        futures = {
            executor.submit(create_one, client, endpoint, payload): idx
            for (idx, endpoint, payload) in requests_to_send
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                ok, data = fut.result()
                results.append((idx, ok, data))
                if ok:
                    successes += 1
                    provider_id = data.get("id") or data.get("provider_id")
                    print(f"[{idx}] ✅ Created provider (id={provider_id})")
                else:
                    failures += 1
                    print(f"[{idx}] ❌ API error: {json.dumps(data, indent=2)}")
            except Exception as e:
                failures += 1
                print(f"[{idx}] ❌ Request failed: {e}")

    print(f"\nDone. Success: {successes}  Failures: {failures}")


if __name__ == "__main__":
    main()
