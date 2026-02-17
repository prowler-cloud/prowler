import os
from typing import Any, Dict, Optional

import requests

from prowler.config.config import (
    cloud_api_base_url,
    cloud_api_ingestion_path,
    cloud_api_key,
)


def send_ocsf_to_api(
    file_path: str,
    *,
    base_url: Optional[str] = None,
    api_key: Optional[str] = None,
    timeout: int = 60,
) -> Dict[str, Any]:
    """Send OCSF file to the Prowler Cloud ingestion endpoint.

    Args:
        file_path: Path to the OCSF JSON file to upload.
        base_url: API base URL. Falls back to PROWLER_CLOUD_API_BASE env var,
                  then to https://api.prowler.com.
        api_key: API key. Falls back to PROWLER_API_KEY env var.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON:API response dict.

    Raises:
        FileNotFoundError: If the OCSF file does not exist.
        ValueError: If no API key is available.
        requests.HTTPError: If the API returns an error status.
    """
    if not file_path:
        raise ValueError("No OCSF file path provided.")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"OCSF file not found: {file_path}")

    api_key = api_key or cloud_api_key
    if not api_key:
        raise ValueError("Missing API key. Set PROWLER_API_KEY environment variable.")

    base_url = base_url or cloud_api_base_url
    base_url = base_url.rstrip("/")
    if not base_url.lower().startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    url = f"{base_url}{cloud_api_ingestion_path}"

    with open(file_path, "rb") as fh:
        response = requests.post(
            url,
            headers={
                "Authorization": f"Api-Key {api_key}",
                "Accept": "application/vnd.api+json",
            },
            files={"file": (os.path.basename(file_path), fh, "application/json")},
            timeout=timeout,
        )
    response.raise_for_status()
    return response.json() if response.text else {}
