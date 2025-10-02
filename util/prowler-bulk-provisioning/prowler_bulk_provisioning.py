#!/usr/bin/env python3

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


def sanitize_sensitive_data(data: Any, depth: int = 0) -> Any:
    """
    Recursively sanitize sensitive data in dictionaries and lists.
    Replaces sensitive field values with masked versions.
    """
    if depth > 10:  # Prevent infinite recursion
        return data

    # List of sensitive field names to mask
    sensitive_fields = {
        "password",
        "secret",
        "token",
        "key",
        "credentials",
        "client_secret",
        "refresh_token",
        "access_key_id",
        "secret_access_key",
        "session_token",
        "private_key",
        "api_key",
        "apikey",
        "auth",
        "authorization",
        "private_key_id",
        "client_id",
        "tenant_id",
        "service_account_key",
        "kubeconfig",
        "role_arn",
        "external_id",
    }

    if isinstance(data, dict):
        sanitized = {}
        for key, value in data.items():
            # Check if the key name suggests sensitive data
            key_lower = key.lower()
            if any(sensitive in key_lower for sensitive in sensitive_fields):
                if isinstance(value, str) and value:
                    # Mask the value but show first few chars for debugging
                    if len(value) > 8:
                        sanitized[key] = (
                            f"{value[:4]}...{value[-2:]}" if len(value) > 6 else "***"
                        )
                    else:
                        sanitized[key] = "***"
                elif isinstance(value, (dict, list)):
                    # Still recurse into nested structures
                    sanitized[key] = sanitize_sensitive_data(value, depth + 1)
                else:
                    sanitized[key] = "***" if value else value
            else:
                # Recurse into non-sensitive fields
                if isinstance(value, (dict, list)):
                    sanitized[key] = sanitize_sensitive_data(value, depth + 1)
                else:
                    sanitized[key] = value
        return sanitized
    elif isinstance(data, list):
        return [sanitize_sensitive_data(item, depth + 1) for item in data]
    else:
        return data


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
                    except Exception:
                        sys.exit("Invalid JSON in 'credentials' column")
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


def build_payload(
    item: Dict[str, Any],
) -> Tuple[str, Dict[str, Any], Optional[Dict[str, Any]]]:
    """
    Returns (endpoint_path, provider_payload, secret_payload) to POST.

    The API requires two steps:
    1. Create provider with minimal info
    2. Create secret linked to the provider
    """
    provider = str(item.get("provider", "")).strip().lower()
    uid = item.get("uid")  # account id / subscription id / project id / etc.
    alias = item.get("alias")
    auth_method = str(item.get("auth_method", "")).strip().lower()
    creds: Dict[str, Any] = item.get("credentials") or {}

    if not provider or not uid:
        raise ValueError("Each item must include 'provider' and 'uid'.")

    # Step 1: Build provider creation payload (minimal)
    provider_payload: Dict[str, Any] = {
        "data": {
            "type": "providers",
            "attributes": {
                "provider": provider,
                "uid": uid,
                "alias": alias,
            },
        }
    }

    # Step 2: Build secret creation payload if credentials are provided
    secret_payload: Optional[Dict[str, Any]] = None

    if auth_method and creds:
        # Determine secret_type based on auth_method and provider
        if auth_method == "role":
            secret_type = "role"
        elif provider == "gcp" and auth_method in [
            "service_account",
            "service_account_json",
        ]:
            secret_type = "service_account"
        else:
            secret_type = "static"
        secret_data: Dict[str, Any] = {}

        if provider == "aws":
            if auth_method == "role":
                external_id = creds.get("external_id")
                if not external_id:
                    raise ValueError(
                        "AWS role authentication requires 'external_id' in credentials"
                    )
                secret_data = {
                    "role_arn": creds.get("role_arn"),
                    "external_id": external_id,
                }
                # Optional fields for role
                if creds.get("session_name"):
                    secret_data["role_session_name"] = creds.get("session_name")
                if creds.get("duration_seconds"):
                    secret_data["session_duration"] = creds.get("duration_seconds")
                if creds.get("access_key_id"):
                    secret_data["aws_access_key_id"] = creds.get("access_key_id")
                if creds.get("secret_access_key"):
                    secret_data["aws_secret_access_key"] = creds.get(
                        "secret_access_key"
                    )
                if creds.get("session_token"):
                    secret_data["aws_session_token"] = creds.get("session_token")
            elif auth_method == "credentials":
                secret_type = "static"
                secret_data = {
                    "aws_access_key_id": creds.get("access_key_id"),
                    "aws_secret_access_key": creds.get("secret_access_key"),
                }
                if creds.get("session_token"):
                    secret_data["aws_session_token"] = creds.get("session_token")
            else:
                raise ValueError("AWS 'auth_method' must be 'role' or 'credentials'.")

        elif provider == "azure":
            if auth_method != "service_principal":
                raise ValueError("Azure 'auth_method' must be 'service_principal'.")
            secret_data = {
                "tenant_id": creds.get("tenant_id"),
                "client_id": creds.get("client_id"),
                "client_secret": creds.get("client_secret"),
            }

        elif provider == "gcp":
            # GCP supports 3 authentication methods
            if (
                auth_method == "service_account"
                or auth_method == "service_account_json"
            ):
                # Method 1: Service Account JSON key
                inline = creds.get("inline_json")
                path = creds.get("service_account_key_json_path")

                # Load the service account JSON
                sa_data = None
                if path and not inline:
                    inline_content = read_text_file(path)
                    if inline_content:
                        try:
                            import json

                            sa_data = json.loads(inline_content)
                        except (json.JSONDecodeError, ValueError):
                            # If parsing fails, try sending as string
                            sa_data = {"private_key": inline_content}
                elif inline:
                    if isinstance(inline, dict):
                        sa_data = inline
                    else:
                        try:
                            import json

                            sa_data = json.loads(inline)
                        except (json.JSONDecodeError, ValueError):
                            sa_data = {"private_key": inline}

                # The API expects the service account JSON wrapped in a service_account_key field
                if sa_data and isinstance(sa_data, dict):
                    # Wrap the service account JSON in the service_account_key field
                    secret_data = {"service_account_key": sa_data}
                else:
                    raise ValueError("Could not parse service account JSON")

            elif auth_method == "oauth2" or auth_method == "adc":
                # Method 2: OAuth2 credentials (Application Default Credentials)
                secret_data = {
                    "client_id": creds.get("client_id"),
                    "client_secret": creds.get("client_secret"),
                    "refresh_token": creds.get("refresh_token"),
                }
            elif (
                auth_method == "workload_identity"
                or auth_method == "workload_identity_federation"
            ):
                # Method 3: Workload Identity Federation
                secret_data = {
                    "type": creds.get("type", "external_account"),
                    "audience": creds.get("audience"),
                    "subject_token_type": creds.get("subject_token_type"),
                    "service_account_impersonation_url": creds.get(
                        "service_account_impersonation_url"
                    ),
                    "token_url": creds.get("token_url"),
                    "credential_source": creds.get("credential_source"),
                }
            else:
                raise ValueError(
                    "GCP 'auth_method' must be 'service_account', 'oauth2', or 'workload_identity'."
                )

        elif provider == "kubernetes":
            if auth_method != "kubeconfig":
                raise ValueError("Kubernetes 'auth_method' must be 'kubeconfig'.")
            inline = creds.get("kubeconfig_inline")
            path = creds.get("kubeconfig_path")
            if path and not inline:
                inline = read_text_file(path)
            secret_data = {"kubeconfig_content": inline}

        elif provider == "m365":
            # M365 is not in the API schema, might need special handling
            if auth_method != "service_principal":
                raise ValueError("M365 'auth_method' must be 'service_principal'.")
            secret_data = {
                "tenant_id": creds.get("tenant_id"),
                "client_id": creds.get("client_id"),
                "client_secret": creds.get("client_secret"),
            }
            # User/password might be additional fields
            if creds.get("username"):
                secret_data["user"] = creds.get("username")
            if creds.get("password"):
                secret_data["password"] = creds.get("password")

        elif provider == "github":
            if auth_method == "personal_access_token":
                secret_data = {"personal_access_token": creds.get("token")}
            elif auth_method == "oauth_app_token":
                secret_data = {"oauth_app_token": creds.get("oauth_token")}
            elif auth_method == "github_app":
                # Accept inline PK or path
                pk = creds.get("private_key_inline")
                if not pk and creds.get("private_key_path"):
                    pk = read_text_file(creds.get("private_key_path"))
                secret_data = {
                    "github_app_id": int(creds.get("app_id", 0)),
                    "github_app_key": pk,
                }
            else:
                raise ValueError(
                    "GitHub 'auth_method' must be personal_access_token | oauth_app_token | github_app."
                )

        else:
            raise ValueError(f"Unsupported provider: {provider}")

        # Build secret payload
        secret_payload = {
            "data": {
                "type": "provider-secrets",
                "attributes": {
                    "secret_type": secret_type,
                    "secret": secret_data,
                    "name": alias,  # Use alias as the secret name
                },
                "relationships": {
                    "provider": {
                        "data": {
                            "type": "providers",
                            "id": None,  # Will be filled after provider creation
                        }
                    }
                },
            }
        }

    # Return both payloads
    return "/providers", provider_payload, secret_payload


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

    def get(self, path: str) -> requests.Response:
        """Make GET request to API endpoint."""
        url = f"{self.base_url}{path}"
        return requests.get(
            url,
            headers=self._headers(),
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
    client: ApiClient,
    provider_endpoint: str,
    provider_payload: Dict[str, Any],
    secret_payload: Optional[Dict[str, Any]] = None,
    test_provider: bool = False,
) -> Tuple[bool, Dict[str, Any]]:
    """Create a single provider with optional secret using two-step process."""
    # Step 1: Create provider
    resp = client.post(provider_endpoint, provider_payload)
    try:
        data = resp.json()
    except ValueError:
        data = {"text": resp.text}

    if not (200 <= resp.status_code < 300):
        return False, {"status": resp.status_code, "body": data, "step": "provider"}

    provider_id = data.get("data", {}).get("id")
    if not provider_id:
        return False, {"error": "No provider ID returned", "body": data}

    result = {"provider": data}

    # Step 2: Create secret if provided
    if secret_payload:
        # Update the provider ID in the secret payload
        secret_payload["data"]["relationships"]["provider"]["data"]["id"] = provider_id

        # POST to /providers/secrets endpoint
        secret_resp = client.post("/providers/secrets", secret_payload)
        try:
            secret_data = secret_resp.json()
        except ValueError:
            secret_data = {"text": secret_resp.text}

        if not (200 <= secret_resp.status_code < 300):
            # Provider was created but secret failed
            result["secret_error"] = {
                "status": secret_resp.status_code,
                "body": secret_data,
            }
            return False, result

        result["secret"] = secret_data

    # Step 3: Test connection if requested
    if test_provider:
        connection_result = test_provider_connection(client, provider_id)
        result["connection_test"] = connection_result

    return True, result


def test_provider_connection(client: ApiClient, provider_id: str) -> Dict[str, Any]:
    """Test connection for a provider."""
    try:
        # Trigger connection test
        resp = client.post(f"/providers/{provider_id}/connection", {})
        if resp.status_code in [200, 202]:
            # Wait a bit for the connection test to complete
            time.sleep(2)

            # Check the connection status
            status_resp = client.get(f"/providers/{provider_id}")
            if status_resp.status_code == 200:
                provider_data = status_resp.json()
                connection = (
                    provider_data.get("data", {})
                    .get("attributes", {})
                    .get("connection", {})
                )
                return {
                    "success": True,
                    "connected": connection.get("connected"),
                    "last_checked_at": connection.get("last_checked_at"),
                }

        return {
            "success": False,
            "error": f"Connection test failed with status {resp.status_code}",
        }
    except Exception as e:
        return {"success": False, "error": str(e)}


def find_existing_provider(client: ApiClient, provider: str, uid: str) -> Optional[str]:
    """Find an existing provider by provider type and UID."""
    try:
        # Query for the specific provider
        resp = client.get(f"/providers?filter[provider]={provider}&filter[uid]={uid}")
        if resp.status_code == 200:
            data = resp.json()
            providers = data.get("data", [])
            if providers:
                return providers[0].get("id")
    except Exception:
        pass
    return None


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
    parser.add_argument(
        "--test-provider",
        type=lambda x: x.lower() in ["true", "1", "yes"],
        default=True,
        help="Test provider connection after creating each provider (default: true). Use --test-provider false to disable.",
    )
    parser.add_argument(
        "--test-provider-only",
        action="store_true",
        help="Only test connections for existing providers (skip creation).",
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

    # Handle test-only mode
    if args.test_provider_only:
        print(
            "Running in test-only mode: checking connections for existing providers..."
        )
        tested, connected, failed = 0, 0, 0

        for idx, item in enumerate(items, start=1):
            provider = str(item.get("provider", "")).strip().lower()
            uid = item.get("uid")
            alias = item.get("alias", "")

            if not provider or not uid:
                print(f"[{idx}] ❌ Skipping: missing provider or uid")
                continue

            # Find existing provider
            provider_id = find_existing_provider(client, provider, uid)
            if not provider_id:
                print(f"[{idx}] ⚠️  Provider not found: {provider}/{uid} ({alias})")
                continue

            print(f"[{idx}] Testing connection for {provider}/{uid} ({alias})...")
            result = test_provider_connection(client, provider_id)
            tested += 1

            if result.get("success"):
                if result.get("connected"):
                    connected += 1
                    print(f"[{idx}] ✅ Connected successfully")
                else:
                    failed += 1
                    print(f"[{idx}] ❌ Connection failed")
            else:
                failed += 1
                # Sanitize error message to avoid potential sensitive data
                error = str(result.get("error", "Unknown error"))
                if any(
                    word in error.lower()
                    for word in [
                        "key",
                        "secret",
                        "token",
                        "password",
                        "credential",
                        "bearer",
                    ]
                ):
                    print(f"[{idx}] ❌ Test failed: Authentication error")
                else:
                    print(f"[{idx}] ❌ Test failed: {error}")

        print(
            f"\nConnection Test Results: Tested: {tested}, Connected: {connected}, Failed: {failed}"
        )
        return

    # Regular mode: create providers
    requests_to_send: List[
        Tuple[int, str, Dict[str, Any], Optional[Dict[str, Any]]]
    ] = []
    for idx, item in enumerate(items, start=1):
        try:
            endpoint, provider_payload, secret_payload = build_payload(item)
        except Exception as e:
            # Sanitize exception message to avoid leaking sensitive data
            error_msg = str(e)
            if any(
                word in error_msg.lower()
                for word in ["key", "secret", "token", "password", "credential"]
            ):
                print(
                    f"[{idx}] ❌ Skipping item due to build error: Invalid credentials format"
                )
            else:
                print(f"[{idx}] ❌ Skipping item due to build error: {error_msg}")
            continue

        # Allow overriding endpoint path globally (for standard creation)
        if endpoint == "/providers":
            endpoint = args.providers_endpoint

        if args.dry_run:
            print(f"[{idx}] DRY-RUN → Provider Creation")
            print(f"  POST {base_url}{endpoint}")
            # Sanitize provider payload (usually safe but might contain some sensitive data)
            sanitized_provider = sanitize_sensitive_data(provider_payload)
            print(f"  {json.dumps(sanitized_provider, indent=2)}")
            if secret_payload:
                print("\n  Then Secret Creation:")
                print(f"  POST {base_url}/providers/secrets")
                # Always sanitize secret payload as it contains credentials
                sanitized_secret = sanitize_sensitive_data(secret_payload)
                print(f"  {json.dumps(sanitized_secret, indent=2)}")
            if args.test_provider:
                print("\n  Then Test Connection")
            print()
        else:
            requests_to_send.append((idx, endpoint, provider_payload, secret_payload))

    if args.dry_run or not requests_to_send:
        if not requests_to_send:
            print("Nothing to send.")
        return

    successes, failures = 0, 0
    results: List[Tuple[int, bool, Dict[str, Any]]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        futures = {
            executor.submit(
                create_one,
                client,
                endpoint,
                provider_payload,
                secret_payload,
                args.test_provider,
            ): idx
            for (idx, endpoint, provider_payload, secret_payload) in requests_to_send
        }
        for fut in as_completed(futures):
            idx = futures[fut]
            try:
                ok, data = fut.result()
                results.append((idx, ok, data))
                if ok:
                    successes += 1
                    provider_id = data.get("provider", {}).get("data", {}).get("id")
                    print(f"[{idx}] ✅ Created provider (id={provider_id})")
                    if "secret" in data:
                        secret_id = data.get("secret", {}).get("data", {}).get("id")
                        print(f"[{idx}] ✅ Created secret (id={secret_id})")
                    if "connection_test" in data:
                        conn = data["connection_test"]
                        if conn.get("success") and conn.get("connected"):
                            print(f"[{idx}] ✅ Connection test: Connected")
                        elif conn.get("success"):
                            print(f"[{idx}] ⚠️  Connection test: Not connected")
                        else:
                            # Sanitize error message to avoid potential sensitive data
                            error = str(conn.get("error", "Unknown error"))
                            if any(
                                word in error.lower()
                                for word in [
                                    "key",
                                    "secret",
                                    "token",
                                    "password",
                                    "credential",
                                    "bearer",
                                ]
                            ):
                                print(
                                    f"[{idx}] ❌ Connection test failed: Authentication error"
                                )
                            else:
                                print(f"[{idx}] ❌ Connection test failed: {error}")
                else:
                    failures += 1
                    if "secret_error" in data:
                        print(f"[{idx}] ⚠️  Provider created but secret failed:")
                        # Sanitize error data which might contain sensitive information
                        sanitized_error = sanitize_sensitive_data(data["secret_error"])
                        print(f"     {json.dumps(sanitized_error, indent=2)}")
                    else:
                        # Sanitize general error data
                        sanitized_data = sanitize_sensitive_data(data)
                        print(
                            f"[{idx}] ❌ API error: {json.dumps(sanitized_data, indent=2)}"
                        )
            except Exception as e:
                failures += 1
                # Sanitize exception message to avoid leaking sensitive data
                error_msg = str(e)
                if any(
                    word in error_msg.lower()
                    for word in [
                        "key",
                        "secret",
                        "token",
                        "password",
                        "credential",
                        "bearer",
                    ]
                ):
                    print(f"[{idx}] ❌ Request failed: Authentication or network error")
                else:
                    print(f"[{idx}] ❌ Request failed: {error_msg}")

    print(f"\nDone. Success: {successes}  Failures: {failures}")


if __name__ == "__main__":
    main()
