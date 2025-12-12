from typing import Optional

from pydantic.v1 import BaseModel, Field

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.models import CloudflareAccount


class Zones(CloudflareService):
    """Retrieve Cloudflare zones with security-relevant settings."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones_map: dict[str, "CloudflareZone"] = {
            zone.id: zone for zone in self.zones
        }
        self.__threading_call__(self._enrich_zone)
        self.zones = list(self.zones_map.values())

    def _get_setting(self, zone_id: str, setting_id: str):
        """Get a single zone setting by ID."""
        try:
            result = self.client.zones.settings.get(
                setting_id=setting_id, zone_id=zone_id
            )
            return getattr(result, "value", None)
        except Exception:
            return None

    def _fetch_zone_settings(self, zone_id: str) -> "CloudflareZoneSettings":
        """Fetch all required zone settings."""
        settings = {
            setting_id: self._get_setting(zone_id, setting_id)
            for setting_id in [
                "always_use_https",
                "min_tls_version",
                "ssl",
                "tls_1_3",
                "automatic_https_rewrites",
                "universal_ssl",
                "security_header",
                "waf",
                "security_level",
                "browser_check",
                "challenge_ttl",
                "ip_geolocation",
                "email_obfuscation",
                "server_side_exclude",
                "hotlink_protection",
                "development_mode",
                "always_online",
            ]
        }

        # Parse HSTS settings from security_header
        security_header = settings.get("security_header")
        # Handle Cloudflare SDK object or dict
        if hasattr(security_header, "strict_transport_security"):
            sts = security_header.strict_transport_security
            strict_transport_security_data = {
                "enabled": getattr(sts, "enabled", False),
                "max_age": getattr(sts, "max_age", 0),
                "include_subdomains": getattr(sts, "include_subdomains", False),
                "preload": getattr(sts, "preload", False),
                "nosniff": getattr(sts, "nosniff", False),
            }
        elif isinstance(security_header, dict):
            strict_transport_security_data = security_header.get(
                "strict_transport_security", {}
            )
        else:
            strict_transport_security_data = {}

        strict_transport_security = StrictTransportSecurity(
            enabled=strict_transport_security_data.get("enabled", False),
            max_age=strict_transport_security_data.get("max_age", 0),
            include_subdomains=strict_transport_security_data.get(
                "include_subdomains", False
            ),
            preload=strict_transport_security_data.get("preload", False),
            nosniff=strict_transport_security_data.get("nosniff", False),
        )

        return CloudflareZoneSettings(
            always_use_https=settings.get("always_use_https"),
            min_tls_version=str(settings.get("min_tls_version") or ""),
            ssl_encryption_mode=settings.get("ssl"),
            tls_1_3=settings.get("tls_1_3"),
            automatic_https_rewrites=settings.get("automatic_https_rewrites"),
            universal_ssl=settings.get("universal_ssl"),
            strict_transport_security=strict_transport_security,
            waf=settings.get("waf"),
            security_level=settings.get("security_level"),
            browser_check=settings.get("browser_check"),
            challenge_ttl=settings.get("challenge_ttl"),
            ip_geolocation=settings.get("ip_geolocation"),
            email_obfuscation=settings.get("email_obfuscation"),
            server_side_exclude=settings.get("server_side_exclude"),
            hotlink_protection=settings.get("hotlink_protection"),
            development_mode=settings.get("development_mode"),
            always_online=settings.get("always_online"),
        )

    def _enrich_zone(self, zone: "CloudflareZone") -> None:
        """Enrich zone with settings and DNSSEC status."""
        try:
            zone.settings = self._fetch_zone_settings(zone.id)

            dnssec = self.client.dns.dnssec.get(zone_id=zone.id)
            zone.dnssec_status = getattr(dnssec, "status", None)
            self.zones_map[zone.id] = zone
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


class StrictTransportSecurity(BaseModel):
    """HTTP Strict Transport Security (HSTS) settings."""

    enabled: bool = False
    max_age: int = 0
    include_subdomains: bool = False
    preload: bool = False
    nosniff: bool = False


class CloudflareZoneSettings(BaseModel):
    """Selected Cloudflare zone security settings."""

    # TLS/SSL settings
    always_use_https: Optional[str] = None
    min_tls_version: Optional[str] = None
    ssl_encryption_mode: Optional[str] = None
    tls_1_3: Optional[str] = None
    automatic_https_rewrites: Optional[str] = None
    universal_ssl: Optional[str] = None
    # HSTS settings
    strict_transport_security: StrictTransportSecurity = Field(
        default_factory=StrictTransportSecurity
    )
    # Security settings
    waf: Optional[str] = None
    security_level: Optional[str] = None
    browser_check: Optional[str] = None
    challenge_ttl: Optional[int] = None
    ip_geolocation: Optional[str] = None
    # Scrape Shield settings
    email_obfuscation: Optional[str] = None
    server_side_exclude: Optional[str] = None
    hotlink_protection: Optional[str] = None
    # Zone state
    development_mode: Optional[str] = None
    always_online: Optional[str] = None


class CloudflareZone(BaseModel):
    """Cloudflare zone representation used across services."""

    id: str
    name: str
    status: Optional[str] = None
    paused: bool = False
    account: Optional[CloudflareAccount] = None
    plan: Optional[str] = None
    settings: CloudflareZoneSettings = Field(default_factory=CloudflareZoneSettings)
    dnssec_status: Optional[str] = None
