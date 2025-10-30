from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class SSL(CloudflareService):
    """Cloudflare SSL/TLS service for managing SSL settings"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones = self._list_zones()
        self.ssl_settings = self._get_ssl_settings()

    def _list_zones(self) -> dict:
        """
        List all Cloudflare zones

        Returns:
            dict: Dictionary of zones keyed by zone ID
        """
        logger.info("SSL - Listing Zones...")
        zones = {}

        try:
            # If specific zone IDs are provided, use those
            if self.provider.zone_ids:
                for zone_id in self.provider.zone_ids:
                    zone_data = self._api_request("GET", f"/zones/{zone_id}")
                    if zone_data:
                        zones[zone_data["id"]] = Zone(
                            id=zone_data["id"],
                            name=zone_data["name"],
                            account_id=zone_data.get("account", {}).get("id", ""),
                        )
            else:
                # List all zones
                all_zones = self._api_request_paginated("/zones")
                for zone_data in all_zones:
                    zones[zone_data["id"]] = Zone(
                        id=zone_data["id"],
                        name=zone_data["name"],
                        account_id=zone_data.get("account", {}).get("id", ""),
                    )

            logger.info(f"Found {len(zones)} zone(s) for SSL checks")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return zones

    def _get_ssl_settings(self) -> dict:
        """
        Get SSL/TLS settings for all zones

        Returns:
            dict: Dictionary of SSL settings keyed by zone ID
        """
        logger.info("SSL - Getting SSL/TLS Settings...")
        ssl_settings = {}

        try:
            for zone_id, zone in self.zones.items():
                # Get SSL/TLS mode
                ssl_mode = self._api_request("GET", f"/zones/{zone_id}/settings/ssl")

                # Get minimum TLS version
                min_tls = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/min_tls_version"
                )

                # Get TLS 1.3 setting
                tls_1_3 = self._api_request("GET", f"/zones/{zone_id}/settings/tls_1_3")

                # Get automatic HTTPS rewrites
                auto_https = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/automatic_https_rewrites"
                )

                # Get always use HTTPS
                always_https = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/always_use_https"
                )

                # Get opportunistic encryption
                opportunistic = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/opportunistic_encryption"
                )

                # Get HSTS settings
                hsts = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/security_header"
                )

                ssl_settings[zone_id] = SSLSettings(
                    zone_id=zone_id,
                    zone_name=zone.name,
                    ssl_mode=ssl_mode.get("value", "") if ssl_mode else "",
                    min_tls_version=(min_tls.get("value", "") if min_tls else "1.0"),
                    tls_1_3_enabled=(
                        tls_1_3.get("value", "off") == "on" if tls_1_3 else False
                    ),
                    automatic_https_rewrites=(
                        auto_https.get("value", "off") == "on" if auto_https else False
                    ),
                    always_use_https=(
                        always_https.get("value", "off") == "on"
                        if always_https
                        else False
                    ),
                    opportunistic_encryption=(
                        opportunistic.get("value", "off") == "on"
                        if opportunistic
                        else False
                    ),
                    hsts_enabled=(
                        hsts.get("value", {})
                        .get("strict_transport_security", {})
                        .get("enabled", False)
                        if hsts
                        else False
                    ),
                    hsts_max_age=(
                        hsts.get("value", {})
                        .get("strict_transport_security", {})
                        .get("max_age", 0)
                        if hsts
                        else 0
                    ),
                    hsts_include_subdomains=(
                        hsts.get("value", {})
                        .get("strict_transport_security", {})
                        .get("include_subdomains", False)
                        if hsts
                        else False
                    ),
                    hsts_preload=(
                        hsts.get("value", {})
                        .get("strict_transport_security", {})
                        .get("preload", False)
                        if hsts
                        else False
                    ),
                )

            logger.info(f"Retrieved SSL settings for {len(ssl_settings)} zone(s)")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return ssl_settings


class Zone(BaseModel):
    """Model for Cloudflare Zone"""

    id: str
    name: str
    account_id: str


class SSLSettings(BaseModel):
    """Model for Cloudflare SSL/TLS Settings"""

    zone_id: str
    zone_name: str
    ssl_mode: str
    min_tls_version: str
    tls_1_3_enabled: bool
    automatic_https_rewrites: bool
    always_use_https: bool
    opportunistic_encryption: bool
    hsts_enabled: bool
    hsts_max_age: int
    hsts_include_subdomains: bool
    hsts_preload: bool
