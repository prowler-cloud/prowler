"""Published-app HTTP inspector.

Fetches each published Lovable app's HTML and a sample of its bundled JS
to evaluate runtime security signals that the Cloud API does not expose:

  - HTTP security headers (CSP, HSTS, X-Frame-Options, ...)
  - HTTPS / HSTS posture
  - Secrets accidentally bundled into the frontend
"""

import re
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.lovable.config import (
    LOVABLE_DEFAULT_TIMEOUT,
    LOVABLE_USER_AGENT,
    REQUIRED_SECURITY_HEADERS,
    SECRET_PATTERNS,
)
from prowler.providers.lovable.lib.service.service import LovableService

# Cap how much of each bundle we read; secret scan only needs a sample.
MAX_BUNDLE_BYTES = 1_500_000
MAX_BUNDLES_PER_APP = 5
SCRIPT_SRC_REGEX = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)
COMPILED_SECRET_PATTERNS = tuple((re.compile(p), label) for p, label in SECRET_PATTERNS)


class PublishedAppInspection(BaseModel):
    """Result of inspecting a single published app over HTTP."""

    app_id: str
    app_name: str
    workspace_id: str = ""
    published_url: Optional[str] = None

    reachable: bool = False
    is_https: bool = False
    status_code: Optional[int] = None

    headers: dict[str, str] = Field(default_factory=dict)
    missing_security_headers: list[str] = Field(default_factory=list)
    has_strict_csp: bool = False

    bundles_inspected: list[str] = Field(default_factory=list)
    leaked_secrets: list[dict] = Field(default_factory=list)

    # required by CheckReportLovable
    name: str = ""
    id: str = ""


class Published(LovableService):
    """Live HTTP inspection of published Lovable apps."""

    def __init__(self, provider):
        super().__init__("Published", provider)
        self.inspections: dict[str, PublishedAppInspection] = {}

        from prowler.providers.lovable.services.apps.apps_client import apps_client

        published_apps = [app for app in apps_client.apps.values() if app.is_published]
        self.__threading_call__(self._inspect_app, published_apps)

    def _inspect_app(self, app) -> None:
        if not app.published_url:
            return

        inspection = PublishedAppInspection(
            app_id=app.id,
            app_name=app.name,
            workspace_id=app.workspace_id,
            published_url=app.published_url,
            id=app.id,
            name=app.name,
        )

        try:
            response = self._fetch(app.published_url)
            inspection.reachable = True
            inspection.status_code = response.status_code
            inspection.is_https = urlparse(app.published_url).scheme == "https"
            inspection.headers = {k.lower(): v for k, v in response.headers.items()}
            inspection.missing_security_headers = [
                header
                for header in REQUIRED_SECURITY_HEADERS
                if header not in inspection.headers
            ]
            inspection.has_strict_csp = self._is_strict_csp(
                inspection.headers.get("content-security-policy", "")
            )

            bundle_urls = self._discover_bundles(
                base_url=app.published_url, html=response.text
            )
            inspection.bundles_inspected = bundle_urls

            for bundle_url in bundle_urls:
                inspection.leaked_secrets.extend(self._scan_bundle(bundle_url))

        except Exception as error:
            logger.warning(
                f"Published - Could not inspect {app.published_url}: "
                f"{error.__class__.__name__}: {error}"
            )

        self.inspections[app.id] = inspection

    def _fetch(self, url: str) -> requests.Response:
        return requests.get(
            url,
            timeout=LOVABLE_DEFAULT_TIMEOUT,
            headers={"User-Agent": LOVABLE_USER_AGENT},
            allow_redirects=True,
        )

    def _discover_bundles(self, base_url: str, html: str) -> list[str]:
        urls: list[str] = []
        for match in SCRIPT_SRC_REGEX.finditer(html or ""):
            src = match.group(1)
            if not src.endswith(".js") and "/assets/" not in src:
                continue
            full = urljoin(base_url, src)
            if full not in urls:
                urls.append(full)
            if len(urls) >= MAX_BUNDLES_PER_APP:
                break
        return urls

    def _scan_bundle(self, url: str) -> list[dict]:
        try:
            response = requests.get(
                url,
                timeout=LOVABLE_DEFAULT_TIMEOUT,
                headers={"User-Agent": LOVABLE_USER_AGENT},
                stream=True,
            )
            content = response.raw.read(MAX_BUNDLE_BYTES, decode_content=True)
            text = content.decode("utf-8", errors="ignore")
            findings: list[dict] = []
            for pattern, label in COMPILED_SECRET_PATTERNS:
                for match in pattern.finditer(text):
                    findings.append(
                        {
                            "type": label,
                            "bundle": url,
                            "match_preview": _redact(match.group(0)),
                        }
                    )
                    if len(findings) > 20:
                        break
                if len(findings) > 20:
                    break
            return findings
        except Exception as error:
            logger.debug(
                f"Published - Bundle scan failed for {url}: "
                f"{error.__class__.__name__}: {error}"
            )
            return []

    @staticmethod
    def _is_strict_csp(csp: str) -> bool:
        if not csp:
            return False
        csp_lower = csp.lower()
        if "default-src" not in csp_lower:
            return False
        # Reject the most dangerous wildcards / inline allowances.
        if "'unsafe-inline'" in csp_lower or "'unsafe-eval'" in csp_lower:
            return False
        if "default-src *" in csp_lower or "script-src *" in csp_lower:
            return False
        return True


def _redact(value: str) -> str:
    """Keep the first 4 and last 4 chars; redact the middle."""
    if len(value) <= 12:
        return "***"
    return f"{value[:4]}...{value[-4:]}"
