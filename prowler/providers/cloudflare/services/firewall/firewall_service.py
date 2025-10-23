from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class Firewall(CloudflareService):
    """Cloudflare Firewall service for managing firewall rules and WAF settings"""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.zones = self._list_zones()
        self.firewall_rules = self._list_firewall_rules()
        self.security_settings = self._get_security_settings()

    def _list_zones(self) -> dict:
        """
        List all Cloudflare zones

        Returns:
            dict: Dictionary of zones keyed by zone ID
        """
        logger.info("Firewall - Listing Zones...")
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
                            status=zone_data.get("status", ""),
                            plan=zone_data.get("plan", {}).get("name", ""),
                        )
            else:
                # List all zones
                all_zones = self._api_request_paginated("/zones")
                for zone_data in all_zones:
                    zones[zone_data["id"]] = Zone(
                        id=zone_data["id"],
                        name=zone_data["name"],
                        account_id=zone_data.get("account", {}).get("id", ""),
                        status=zone_data.get("status", ""),
                        plan=zone_data.get("plan", {}).get("name", ""),
                    )

            logger.info(f"Found {len(zones)} zone(s)")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return zones

    def _list_firewall_rules(self) -> dict:
        """
        List firewall rules for all zones

        Returns:
            dict: Dictionary of firewall rules keyed by rule ID
        """
        logger.info("Firewall - Listing Firewall Rules...")
        firewall_rules = {}

        try:
            for zone_id, zone in self.zones.items():
                # Get firewall rules for the zone
                rules_data = self._api_request_paginated(
                    f"/zones/{zone_id}/firewall/rules"
                )

                for rule in rules_data:
                    firewall_rules[rule["id"]] = FirewallRule(
                        id=rule["id"],
                        zone_id=zone_id,
                        zone_name=zone.name,
                        paused=rule.get("paused", False),
                        description=rule.get("description", ""),
                        action=rule.get("action", ""),
                        priority=rule.get("priority", 0),
                        filter_id=rule.get("filter", {}).get("id", ""),
                    )

                # Get WAF settings for the zone
                waf_settings = self._api_request(
                    "GET", f"/zones/{zone_id}/firewall/waf/packages"
                )
                if waf_settings:
                    zone.waf_enabled = True

            logger.info(f"Found {len(firewall_rules)} firewall rule(s)")

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return firewall_rules

    def _get_security_settings(self) -> dict:
        """
        Get security settings for all zones

        Returns:
            dict: Dictionary of security settings keyed by zone ID
        """
        logger.info("Firewall - Getting Security Settings...")
        security_settings = {}

        try:
            for zone_id, zone in self.zones.items():
                # Get security level
                security_level = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/security_level"
                )

                # Get browser integrity check
                browser_check = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/browser_check"
                )

                # Get challenge passage
                challenge_ttl = self._api_request(
                    "GET", f"/zones/{zone_id}/settings/challenge_ttl"
                )

                security_settings[zone_id] = SecuritySettings(
                    zone_id=zone_id,
                    zone_name=zone.name,
                    security_level=(
                        security_level.get("value", "") if security_level else ""
                    ),
                    browser_integrity_check=(
                        browser_check.get("value", "off") == "on"
                        if browser_check
                        else False
                    ),
                    challenge_ttl=(
                        challenge_ttl.get("value", 0) if challenge_ttl else 0
                    ),
                )

            logger.info(
                f"Retrieved security settings for {len(security_settings)} zone(s)"
            )

        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return security_settings


class Zone(BaseModel):
    """Model for Cloudflare Zone"""

    id: str
    name: str
    account_id: str
    status: str
    plan: str
    waf_enabled: bool = False


class FirewallRule(BaseModel):
    """Model for Cloudflare Firewall Rule"""

    id: str
    zone_id: str
    zone_name: str
    paused: bool
    description: str
    action: str
    priority: int
    filter_id: str


class SecuritySettings(BaseModel):
    """Model for Cloudflare Security Settings"""

    zone_id: str
    zone_name: str
    security_level: str
    browser_integrity_check: bool
    challenge_ttl: int
