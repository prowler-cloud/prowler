"""Check that application registration redirect URIs are secure."""

from urllib.parse import urlparse

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client

# Custom URI schemes used by public clients that are valid and must not be
# flagged as malformed or checked for DNS resolution.
_PUBLIC_CLIENT_CUSTOM_SCHEME_PREFIXES = (
    "msal",
    "ms-appx-web",
    "brk-",
    "com.",
    "msauth.",
)

# Hosts considered loopback and therefore allowed over plain HTTP.
_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}

# Platform domains susceptible to subdomain takeover.
_PLATFORM_DOMAINS = (".azurewebsites.net",)


def _is_custom_scheme_uri(uri: str) -> bool:
    """Return True if the URI uses a known custom scheme for public clients.

    Args:
        uri: The redirect URI string.

    Returns:
        True when the scheme is a recognised custom/native scheme that should
        not be validated further.
    """
    lower = uri.lower()
    if lower.startswith("urn:"):
        return True
    for prefix in _PUBLIC_CLIENT_CUSTOM_SCHEME_PREFIXES:
        if lower.startswith(prefix):
            return True
    return False


def _check_uri(uri: str) -> str | None:
    """Evaluate a single redirect URI for insecure patterns.

    Args:
        uri: The redirect URI string.

    Returns:
        A reason string when the URI is insecure, or None when it is safe.
    """
    # Skip recognised custom schemes (public-client / native).
    if _is_custom_scheme_uri(uri):
        return None

    # Wildcard check (before parsing - wildcards may break urlparse).
    if "*" in uri:
        return "contains wildcard"

    try:
        parsed = urlparse(uri)
    except Exception:
        return "malformed URI"

    scheme = (parsed.scheme or "").lower()
    host = (parsed.hostname or "").lower()

    # A URI that has no scheme or host is malformed.
    if not scheme or not host:
        return "malformed URI"

    # Plain HTTP with a non-loopback host.
    if scheme == "http" and host not in _LOOPBACK_HOSTS:
        return "uses http:// with non-localhost host"

    # Platform domain susceptible to subdomain takeover.
    for domain in _PLATFORM_DOMAINS:
        if host == domain.lstrip(".") or host.endswith(domain):
            return f"host on shared platform domain {domain.lstrip('.')}"

    return None


class entra_app_registration_redirect_uris_secure(Check):
    """Ensure application registration redirect URIs are secure.

    This check evaluates every application registration in the tenant and
    inspects its web, SPA and public-client redirect URIs for insecure
    patterns: plain HTTP on non-loopback hosts, hosts on shared platform
    domains (e.g. azurewebsites.net), wildcard characters, and malformed URIs.

    - PASS: None of the application's redirect URIs match a FAIL condition,
      or the application has no redirect URIs configured.
    - FAIL: At least one redirect URI is insecure; every offending URI and its
      reason are listed in ``status_extended``.
    """

    def execute(self) -> list[CheckReportM365]:
        """Execute the redirect URI security check.

        Returns:
            A list of reports containing the result of the check.
        """
        findings: list[CheckReportM365] = []

        for app_id, app in entra_client.app_registrations.items():
            display_name = app.name or app.app_id
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=app,
                resource_name=display_name,
                resource_id=app_id,
            )

            # Collect all redirect URIs across platforms.
            all_uris = (
                app.web_redirect_uris
                + app.spa_redirect_uris
                + app.public_client_redirect_uris
            )

            # Evaluate each URI.
            insecure: list[str] = []
            for uri in all_uris:
                reason = _check_uri(uri)
                if reason:
                    insecure.append(f"{uri} ({reason})")

            if insecure:
                report.status = "FAIL"
                total = len(insecure)
                if total > 5:
                    displayed = ", ".join(insecure[:5])
                    displayed += f" (and {total - 5} more)"
                else:
                    displayed = ", ".join(insecure)
                report.status_extended = (
                    f"App registration {display_name} has {total} insecure "
                    f"redirect URI(s): {displayed}."
                )
            else:
                report.status = "PASS"
                if all_uris:
                    report.status_extended = (
                        f"App registration {display_name} has all redirect URIs secure."
                    )
                else:
                    report.status_extended = f"App registration {display_name} has no redirect URIs configured."

            findings.append(report)

        return findings
