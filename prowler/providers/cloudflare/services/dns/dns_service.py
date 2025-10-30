from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class DNS(CloudflareService):
    """Cloudflare DNS service for managing DNS settings"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones = self._list_zones()
        self.dnssec_settings = self._get_dnssec_settings()

    def _list_zones(self) -> dict:
        """
        List all Cloudflare zones

        Returns:
            dict: Dictionary of zones keyed by zone ID
        """
        logger.info("DNS - Listing Zones...")
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

            logger.info(f"Found {len(zones)} zone(s) for DNS checks")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return zones

    def _get_dnssec_settings(self) -> dict:
        """
        Get DNSSEC settings for all zones

        Returns:
            dict: Dictionary of DNSSEC settings keyed by zone ID
        """
        logger.info("DNS - Getting DNSSEC Settings...")
        dnssec_settings = {}

        try:
            for zone_id, zone in self.zones.items():
                # Get DNSSEC status
                dnssec = self._api_request("GET", f"/zones/{zone_id}/dnssec")

                dnssec_settings[zone_id] = DNSSECSettings(
                    zone_id=zone_id,
                    zone_name=zone.name,
                    dnssec_enabled=(
                        dnssec.get("status", "disabled") == "active"
                        if dnssec
                        else False
                    ),
                    dnssec_status=(
                        dnssec.get("status", "disabled") if dnssec else "disabled"
                    ),
                )

            logger.info(f"Retrieved DNSSEC settings for {len(dnssec_settings)} zone(s)")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return dnssec_settings


class Zone(BaseModel):
    """Model for Cloudflare Zone"""

    id: str
    name: str
    account_id: str


class DNSSECSettings(BaseModel):
    """Model for Cloudflare DNSSEC Settings"""

    zone_id: str
    zone_name: str
    dnssec_enabled: bool
    dnssec_status: str
