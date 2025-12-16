from typing import Optional

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.services.zones.zones_client import zones_client


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
            for zone in zones_client.zones.values():
                try:
                    # Get all rulesets for the zone
                    rulesets = self.client.rulesets.list(zone_id=zone.id)
                    for ruleset in rulesets:
                        ruleset_id = getattr(ruleset, "id", None)
                        phase = getattr(ruleset, "phase", None)
                        if not ruleset_id:
                            continue

                        # Get rules within each ruleset
                        try:
                            ruleset_detail = self.client.rulesets.get(
                                ruleset_id=ruleset_id, zone_id=zone.id
                            )
                            rules = getattr(ruleset_detail, "rules", []) or []
                            for rule in rules:
                                self.rules.append(
                                    CloudflareFirewallRule(
                                        id=getattr(rule, "id", None),
                                        zone_id=zone.id,
                                        zone_name=zone.name,
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
                                f"{zone.id} ruleset {ruleset_id} -- {error.__class__.__name__}: {error}"
                            )
                except Exception as error:
                    logger.error(
                        f"{zone.id} -- {error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )


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
