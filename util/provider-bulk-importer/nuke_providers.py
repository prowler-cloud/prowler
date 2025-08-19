#!/usr/bin/env python3
"""
Delete ALL providers from Prowler Cloud/App via REST API.

⚠️  WARNING: This script will DELETE ALL PROVIDERS in your Prowler account!
Use with extreme caution. There is no undo.

Environment:
  PROWLER_API_BASE   (default: https://api.prowler.com/api/v1)
  PROWLER_API_TOKEN  (required unless --token is provided)

Usage:
  python nuke_providers.py --confirm
  python nuke_providers.py --confirm --filter-provider aws
  python nuke_providers.py --confirm --filter-alias "prod-*"

Safety features:
  * Requires explicit --confirm flag
  * Shows preview of what will be deleted
  * Optional filters to limit scope
  * Dry-run mode available

Author: Prowler Contributors ✨
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests

# ----------------------------- CLI / Utils --------------------------------- #


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

    def get(self, path: str) -> requests.Response:
        """Make GET request to API endpoint."""
        url = f"{self.base_url}{path}"
        return requests.get(
            url,
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )

    def delete(self, path: str) -> requests.Response:
        """Make DELETE request to API endpoint."""
        url = f"{self.base_url}{path}"
        return requests.delete(
            url,
            headers=self._headers(),
            timeout=self.timeout,
            verify=self.verify_ssl,
        )


def fetch_all_providers(client: ApiClient) -> List[Dict[str, Any]]:
    """Fetch all providers from the API with pagination."""
    all_providers = []
    page = 1
    per_page = 100  # Max allowed by API

    while True:
        try:
            # API uses page[number] and page[size] parameters
            resp = client.get(f"/providers?page[number]={page}&page[size]={per_page}")

            if resp.status_code != 200:
                print(f"Error fetching providers (page {page}): {resp.status_code}")
                print(f"Response: {resp.text}")
                break

            data = resp.json()
            providers = data.get("data", [])

            if not providers:
                break

            all_providers.extend(providers)

            # Check if there's a next page
            links = data.get("links", {})
            if not links.get("next"):
                break

            page += 1

        except Exception as e:
            print(f"Error fetching providers: {e}")
            break

    return all_providers


def apply_filters(
    providers: List[Dict[str, Any]],
    filter_provider: Optional[str] = None,
    filter_alias: Optional[str] = None,
    filter_uid: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Apply filters to provider list."""
    filtered = providers

    if filter_provider:
        filtered = [
            p
            for p in filtered
            if p.get("attributes", {}).get("provider") == filter_provider.lower()
        ]

    if filter_alias:
        filtered = [
            p
            for p in filtered
            if fnmatch.fnmatch(p.get("attributes", {}).get("alias", ""), filter_alias)
        ]

    if filter_uid:
        filtered = [
            p
            for p in filtered
            if fnmatch.fnmatch(p.get("attributes", {}).get("uid", ""), filter_uid)
        ]

    return filtered


def delete_provider(client: ApiClient, provider_id: str) -> Tuple[bool, Dict[str, Any]]:
    """Delete a single provider."""
    try:
        resp = client.delete(f"/providers/{provider_id}")

        if resp.status_code in [200, 202, 204]:
            # 202 means accepted for async processing (which is what Prowler returns)
            # Check if it's a task response
            try:
                data = resp.json()
                if data.get("data", {}).get("type") == "tasks":
                    task_state = data.get("data", {}).get("attributes", {}).get("state")
                    # If it's a deletion task that's available or completed, consider it success
                    if task_state in ["available", "completed"]:
                        return True, {
                            "status": "deleted (async)",
                            "id": provider_id,
                            "task": data,
                        }
            except:
                pass

            return True, {"status": "deleted", "id": provider_id}
        else:
            try:
                data = resp.json()
            except ValueError:
                data = {"text": resp.text}
            return False, {"status": resp.status_code, "body": data}

    except Exception as e:
        return False, {"error": str(e)}


def print_provider_summary(providers: List[Dict[str, Any]]) -> None:
    """Print a summary of providers to be deleted."""
    if not providers:
        print("No providers found matching the criteria.")
        return

    # Group by provider type
    by_type: Dict[str, List[Dict[str, Any]]] = {}
    for p in providers:
        provider_type = p.get("attributes", {}).get("provider", "unknown")
        if provider_type not in by_type:
            by_type[provider_type] = []
        by_type[provider_type].append(p)

    print(f"\n{'=' * 60}")
    print(f"PROVIDERS TO BE DELETED: {len(providers)} total")
    print(f"{'=' * 60}")

    for provider_type, items in sorted(by_type.items()):
        print(f"\n{provider_type.upper()}: {len(items)} providers")
        print("-" * 40)

        # Show first 5 and last 2 if more than 7
        if len(items) > 7:
            for p in items[:5]:
                attrs = p.get("attributes", {})
                print(
                    f"  • {attrs.get('alias', 'N/A'):30} (UID: {attrs.get('uid', 'N/A')})"
                )
            print(f"  ... and {len(items) - 7} more ...")
            for p in items[-2:]:
                attrs = p.get("attributes", {})
                print(
                    f"  • {attrs.get('alias', 'N/A'):30} (UID: {attrs.get('uid', 'N/A')})"
                )
        else:
            for p in items:
                attrs = p.get("attributes", {})
                print(
                    f"  • {attrs.get('alias', 'N/A'):30} (UID: {attrs.get('uid', 'N/A')})"
                )

    print(f"\n{'=' * 60}\n")


# ----------------------------- Main ---------------------------------------- #


def main():
    """Main function to delete providers."""
    parser = argparse.ArgumentParser(
        description="⚠️  DELETE ALL providers from Prowler (use with caution!)"
    )
    parser.add_argument(
        "--confirm",
        action="store_true",
        required=True,
        help="Required confirmation flag to proceed with deletion",
    )
    parser.add_argument(
        "--base-url",
        default=os.getenv("PROWLER_API_BASE", "https://api.prowler.com/api/v1"),
        help="API base URL (default: env PROWLER_API_BASE or Prowler Cloud SaaS)",
    )
    parser.add_argument(
        "--token", default=None, help="Bearer token (default: PROWLER_API_TOKEN)"
    )
    parser.add_argument(
        "--filter-provider",
        help="Only delete specific provider type (aws, azure, gcp, kubernetes, github, m365)",
    )
    parser.add_argument(
        "--filter-alias",
        help="Only delete providers matching alias pattern (supports wildcards: prod-*)",
    )
    parser.add_argument(
        "--filter-uid",
        help="Only delete providers matching UID pattern (supports wildcards: 100000*)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be deleted without actually deleting",
    )
    parser.add_argument(
        "--concurrency",
        type=int,
        default=5,
        help="Number of concurrent deletion requests",
    )
    parser.add_argument(
        "--timeout", type=int, default=60, help="Per-request timeout (seconds)"
    )
    parser.add_argument(
        "--insecure",
        action="store_true",
        help="Disable TLS verification (not recommended)",
    )
    parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip interactive confirmation prompt",
    )

    args = parser.parse_args()

    token = env_or_arg(args.token)
    base_url = normalize_base_url(args.base_url)

    client = ApiClient(
        base_url=base_url,
        token=token,
        verify_ssl=not args.insecure,
        timeout=args.timeout,
    )

    # Fetch all providers
    print("Fetching providers from Prowler...")
    all_providers = fetch_all_providers(client)

    if not all_providers:
        print("No providers found in your account.")
        return

    print(f"Found {len(all_providers)} total providers in your account.")

    # Apply filters
    providers_to_delete = apply_filters(
        all_providers,
        filter_provider=args.filter_provider,
        filter_alias=args.filter_alias,
        filter_uid=args.filter_uid,
    )

    if not providers_to_delete:
        print("No providers match the specified filters.")
        return

    # Show what will be deleted
    print_provider_summary(providers_to_delete)

    if args.dry_run:
        print("DRY RUN MODE - No providers will be deleted.")
        print(f"Would delete {len(providers_to_delete)} providers.")
        return

    # Final confirmation
    if not args.yes:
        print("⚠️  WARNING: This action cannot be undone!")
        print(f"⚠️  You are about to DELETE {len(providers_to_delete)} providers!")
        print()
        response = input("Type 'DELETE ALL' to confirm: ")
        if response != "DELETE ALL":
            print("Cancelled. No providers were deleted.")
            return

    # Perform deletion
    print(f"\nDeleting {len(providers_to_delete)} providers...")

    successes = 0
    failures = 0
    results: List[Tuple[str, bool, Dict[str, Any]]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.concurrency)) as executor:
        futures = {
            executor.submit(delete_provider, client, p.get("id")): (
                p.get("id"),
                p.get("attributes", {}).get("alias", "unknown"),
                p.get("attributes", {}).get("provider", "unknown"),
            )
            for p in providers_to_delete
        }

        for fut in as_completed(futures):
            provider_id, alias, provider_type = futures[fut]
            try:
                ok, data = fut.result()
                results.append((provider_id, ok, data))

                if ok:
                    successes += 1
                    # Check if it was an async deletion
                    if data.get("status") == "deleted (async)":
                        print(
                            f"✅ Deleting: {alias} ({provider_type}/{provider_id}) - queued"
                        )
                    else:
                        print(f"✅ Deleted: {alias} ({provider_type}/{provider_id})")
                else:
                    failures += 1
                    print(f"❌ Failed: {alias} ({provider_type}/{provider_id})")
                    if "body" in data:
                        print(f"   Error: {json.dumps(data['body'], indent=2)}")

            except Exception as e:
                failures += 1
                print(f"❌ Exception deleting {alias}: {e}")

    # Summary with nuclear explosion art if successful
    if successes > 0 and failures == 0:
        # Nuclear explosion ASCII art
        print(
            """
                _.-^^---....,,--
            _--                  --_
            <                        >)
            |                         |
            \._                   _./
                ```--. . , ; .--'''
                    | |   |
                .-=||  | |=-.
                `-=#$%&%$#=-'
                    | ;  :|
            _____.,-#%&$@%#&#~,._____
        """
        )
        print(f"\n{'=' * 60}")
        print("💥 NUCLEAR DELETION COMPLETE 💥")
        print(f"{'=' * 60}")
        print(f"✅ Successfully deleted: {successes} providers")
        print("☢️  All targets eliminated!")
    else:
        print(f"\n{'=' * 60}")
        print("DELETION COMPLETE")
        print(f"{'=' * 60}")
        print(f"✅ Successfully deleted: {successes} providers")
        if failures > 0:
            print(f"❌ Failed to delete: {failures} providers")

    print(f"{'=' * 60}\n")

    # Exit with error code if any failures
    if failures > 0:
        sys.exit(1)


if __name__ == "__main__":
    main()
