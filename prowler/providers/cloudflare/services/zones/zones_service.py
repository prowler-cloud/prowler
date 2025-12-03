from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.models import CloudflareZone, CloudflareZoneSettings

# Settings IDs to fetch from Cloudflare API
SETTINGS_TO_FETCH = [
    # TLS/SSL settings
    "always_use_https",
    "min_tls_version",
    "ssl",
    "tls_1_3",
    "automatic_https_rewrites",
    "universal_ssl",
    "security_header",
    # Security settings
    "waf",
    "security_level",
    "browser_check",
    "challenge_ttl",
    "ip_geolocation",
    # Scrape Shield settings
    "email_obfuscation",
    "server_side_exclude",
    "hotlink_protection",
    # Zone state
    "development_mode",
    "always_online",
]


class Zones(CloudflareService):
    """Retrieve Cloudflare zones with security-relevant settings."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones_map: dict[str, CloudflareZone] = {
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

    def _fetch_zone_settings(self, zone_id: str) -> CloudflareZoneSettings:
        """Fetch all required zone settings."""
        settings = {}
        for setting_id in SETTINGS_TO_FETCH:
            settings[setting_id] = self._get_setting(zone_id, setting_id)

        # Parse HSTS settings from security_header
        security_header = settings.get("security_header") or {}
        strict_transport_security = (
            security_header.get("strict_transport_security", {})
            if isinstance(security_header, dict)
            else {}
        )
        hsts_enabled = strict_transport_security.get("enabled", False)
        hsts_max_age = strict_transport_security.get("max_age", 0)
        hsts_include_subdomains = strict_transport_security.get(
            "include_subdomains", False
        )

        return CloudflareZoneSettings(
            # TLS/SSL settings
            always_use_https=settings.get("always_use_https"),
            min_tls_version=str(settings.get("min_tls_version") or ""),
            ssl_encryption_mode=settings.get("ssl"),
            tls_1_3=settings.get("tls_1_3"),
            automatic_https_rewrites=settings.get("automatic_https_rewrites"),
            universal_ssl=settings.get("universal_ssl"),
            hsts_enabled=hsts_enabled,
            hsts_max_age=hsts_max_age,
            hsts_include_subdomains=hsts_include_subdomains,
            # Security settings
            waf=settings.get("waf"),
            security_level=settings.get("security_level"),
            browser_check=settings.get("browser_check"),
            challenge_ttl=settings.get("challenge_ttl"),
            ip_geolocation=settings.get("ip_geolocation"),
            # Scrape Shield settings
            email_obfuscation=settings.get("email_obfuscation"),
            server_side_exclude=settings.get("server_side_exclude"),
            hotlink_protection=settings.get("hotlink_protection"),
            # Zone state
            development_mode=settings.get("development_mode"),
            always_online=settings.get("always_online"),
        )

    def _enrich_zone(self, zone: CloudflareZone) -> None:
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
