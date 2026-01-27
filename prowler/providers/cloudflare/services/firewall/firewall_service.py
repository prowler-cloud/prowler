from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService


class Firewall(CloudflareService):
    """Retrieve Cloudflare firewall rules for all zones."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.rules: list["CloudflareFirewallRule"] = []
        self._list_rulesets()

    def _list_rulesets(self) -> None:
        """List firewall rulesets for all zones."""
        logger.info("Firewall - Listing firewall rulesets...")
        try:
            # Get zones directly from API to avoid circular dependency with zone_client
            zones = self._get_zones()

            for zone_id, zone_name in zones.items():
                try:
                    # Get all rulesets for the zone
                    rulesets = self.client.rulesets.list(zone_id=zone_id)
                    for ruleset in rulesets:
                        ruleset_id = getattr(ruleset, "id", None)
                        phase = getattr(ruleset, "phase", None)
                        if not ruleset_id:
                            continue

                        # Get rules within each ruleset
                        try:
                            ruleset_detail = self.client.rulesets.get(
                                ruleset_id=ruleset_id, zone_id=zone_id
                            )
                            rules = getattr(ruleset_detail, "rules", []) or []
                            for rule in rules:
                                self.rules.append(
                                    CloudflareFirewallRule(
                                        id=getattr(rule, "id", None),
                                        zone_id=zone_id,
                                        zone_name=zone_name,
                                        ruleset_id=ruleset_id,
                                        phase=phase,
                                        action=getattr(rule, "action", None),
                                        expression=getattr(rule, "expression", None),
                                        description=getattr(rule, "description", None),
                                        enabled=getattr(rule, "enabled", True),
                                    )
                                )
                        except Exception as error:
                            logger.debug(
                                f"{zone_id} ruleset {ruleset_id} -- {error.__class__.__name__}: {error}"
                            )
                except Exception as error:
                    logger.error(
                        f"{zone_id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

    def _get_zones(self) -> dict[str, str]:
        """Get zones directly from Cloudflare API.

        Returns:
            Dictionary mapping zone_id to zone_name.
        """
        zones = {}
        audited_accounts = self.provider.identity.audited_accounts
        filter_zones = self.provider.filter_zones
        seen_zone_ids: set[str] = set()

        try:
            for zone in self.client.zones.list():
                zone_id = getattr(zone, "id", None)
                # Prevent infinite loop - skip if we've seen this zone
                if zone_id in seen_zone_ids:
                    break
                seen_zone_ids.add(zone_id)

                zone_account = getattr(zone, "account", None)
                account_id = getattr(zone_account, "id", None) if zone_account else None

                # Filter by audited accounts
                if audited_accounts and account_id not in audited_accounts:
                    continue

                zone_name = getattr(zone, "name", None)

                # Apply zone filter if specified via --region
                if (
                    filter_zones
                    and zone_id not in filter_zones
                    and zone_name not in filter_zones
                ):
                    continue

                zones[zone_id] = zone_name
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )

        return zones


class CloudflareFirewallRule(BaseModel):
    """Cloudflare firewall rule representation."""

    id: Optional[str] = None
    zone_id: str
    zone_name: str
    ruleset_id: Optional[str] = None
    phase: Optional[str] = None
    action: Optional[str] = None
    expression: Optional[str] = None
    description: Optional[str] = None
    enabled: bool = True
