import os
import ssl
from typing import Any, Dict, Optional

import requests
from requests.adapters import HTTPAdapter

from prowler.config.config import (
    cloud_api_base_url,
    cloud_api_ingestion_path,
    cloud_api_key,
)


class SystemTrustStoreError(RuntimeError):
    """Raised when the operating system trust store cannot be initialized."""


def _load_ca_bundle(ssl_context: ssl.SSLContext, ca_bundle_path: str) -> None:
    """Add a CA bundle file or directory to an existing TLS context."""
    if os.path.isfile(ca_bundle_path):
        ssl_context.load_verify_locations(cafile=ca_bundle_path)
    elif os.path.isdir(ca_bundle_path):
        ssl_context.load_verify_locations(capath=ca_bundle_path)
    else:
        raise FileNotFoundError


class _SystemTrustHTTPAdapter(HTTPAdapter):
    """Use one combined trust context for HTTPS origin connection pools."""

    def __init__(self, ssl_context: ssl.SSLContext) -> None:
        """Initialize the adapter with a preconfigured TLS context.

        Args:
            ssl_context: TLS context used for HTTPS connections.
        """
        self._ssl_context = ssl_context
        super().__init__()

    def build_connection_pool_key_attributes(
        self,
        request: requests.PreparedRequest,
        verify: Any,
        cert: Any = None,
    ) -> tuple[Dict[str, Any], Dict[str, Any]]:
        """Build pool attributes that enforce the configured TLS context.

        Args:
            request: Prepared request used to derive host parameters.
            verify: Certificate verification setting supplied by Requests.
            cert: Optional client certificate configuration.

        Returns:
            Host parameters and connection pool keyword arguments.
        """
        verify = True
        host_params, pool_kwargs = super().build_connection_pool_key_attributes(
            request, verify, cert
        )
        pool_kwargs["ssl_context"] = self._ssl_context
        pool_kwargs["cert_reqs"] = "CERT_REQUIRED"
        pool_kwargs.pop("ca_certs", None)
        pool_kwargs.pop("ca_cert_dir", None)
        return host_params, pool_kwargs

    def cert_verify(self, conn: Any, url: str, verify: Any, cert: Any) -> None:
        """Keep certificate verification in the supplied native context."""
        if verify is not True:
            raise ValueError("TLS certificate verification is required for ingestion.")
        conn.cert_reqs = "CERT_REQUIRED"
        conn.ca_certs = None
        conn.ca_cert_dir = None

    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Use native trust for HTTPS proxies without changing SOCKS support."""
        if proxy.lower().startswith("https://"):
            proxy_kwargs.setdefault("proxy_ssl_context", self._ssl_context)
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class _SystemTrustSession(requests.Session):
    """Requests session using native trust augmented with compatibility roots."""

    def __init__(self) -> None:
        super().__init__()
        try:
            import truststore

            ssl_context = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            _load_ca_bundle(ssl_context, requests.certs.where())
            configured_ca_bundle = os.environ.get(
                "REQUESTS_CA_BUNDLE"
            ) or os.environ.get("CURL_CA_BUNDLE")
            if configured_ca_bundle:
                _load_ca_bundle(ssl_context, configured_ca_bundle)
            ssl_context.check_hostname = True
            ssl_context.verify_mode = ssl.CERT_REQUIRED
        except Exception as error:
            self.close()
            raise SystemTrustStoreError(
                "Could not initialize the operating system trust store. "
                "Check the configured CA bundle paths."
            ) from error

        self.mount("https://", _SystemTrustHTTPAdapter(ssl_context))

    def merge_environment_settings(
        self,
        url: str,
        proxies: Optional[Dict[str, str]],
        stream: Optional[bool],
        verify: Any,
        cert: Any,
    ) -> Dict[str, Any]:
        """Preserve environment proxies without replacing the prepared context."""
        verify = False
        settings = super().merge_environment_settings(
            url, proxies, stream, verify, cert
        )
        settings["verify"] = True
        return settings


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
        base_url: API base URL. Falls back to PROWLER_CLOUD_API_BASE_URL env var,
                  then to https://api.prowler.com.
        api_key: API key. Falls back to PROWLER_CLOUD_API_KEY env var.
        timeout: Request timeout in seconds.

    Returns:
        Parsed JSON:API response dict.

    Raises:
        FileNotFoundError: If the OCSF file does not exist.
        ValueError: If no API key is available.
        SystemTrustStoreError: If the operating system trust store cannot initialize.
        requests.HTTPError: If the API returns an error status.
    """
    if not file_path:
        raise ValueError("No OCSF file path provided.")

    if not os.path.isfile(file_path):
        raise FileNotFoundError(f"OCSF file not found: {file_path}")

    api_key = api_key or cloud_api_key
    if not api_key:
        raise ValueError(
            "Missing API key. Set PROWLER_CLOUD_API_KEY environment variable."
        )

    base_url = base_url or cloud_api_base_url
    base_url = base_url.rstrip("/")
    if not base_url.lower().startswith(("http://", "https://")):
        base_url = f"https://{base_url}"

    url = f"{base_url}{cloud_api_ingestion_path}"

    session = _SystemTrustSession()
    try:
        with open(file_path, "rb") as fh:
            response = session.post(
                url,
                headers={
                    "Authorization": f"Api-Key {api_key}",
                    "Accept": "application/vnd.api+json",
                },
                files={
                    "file": (
                        os.path.basename(file_path),
                        fh,
                        "application/json",
                    )
                },
                timeout=timeout,
                allow_redirects=False,
            )
        if 300 <= response.status_code < 400:
            raise requests.HTTPError(
                f"Prowler Cloud ingestion refused HTTP redirect {response.status_code}.",
                response=response,
            )
        response.raise_for_status()
        return response.json() if response.text else {}
    finally:
        session.close()
