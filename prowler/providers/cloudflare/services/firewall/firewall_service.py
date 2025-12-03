from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.models import CloudflareZone


class CloudflareFirewallRule(BaseModel):
    """Represents a firewall rule from custom rulesets."""

    id: str
    name: str = ""
    description: Optional[str] = None
    action: Optional[str] = None
    enabled: bool = True
    expression: Optional[str] = None
    phase: Optional[str] = None
    zone: CloudflareZone

    class Config:
        arbitrary_types_allowed = True


class Firewall(CloudflareService):
    """Collect Cloudflare firewall rules for each zone using rulesets API."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.rules: list[CloudflareFirewallRule] = []
        self.__threading_call__(self._list_firewall_rules)

    def _list_firewall_rules(self, zone: CloudflareZone):
        """List firewall rules from custom rulesets for a zone."""
        seen_ruleset_ids: set[str] = set()
        try:
            for ruleset in self.client.rulesets.list(zone_id=zone.id):
                ruleset_id = getattr(ruleset, "id", "")
                if ruleset_id in seen_ruleset_ids:
                    break
                seen_ruleset_ids.add(ruleset_id)

                ruleset_phase = getattr(ruleset, "phase", "")
                if ruleset_phase in [
                    "http_request_firewall_custom",
                    "http_ratelimit",
                    "http_request_firewall_managed",
                ]:
                    try:
                        ruleset_detail = self.client.rulesets.get(
                            ruleset_id=ruleset_id, zone_id=zone.id
                        )
                        rules = getattr(ruleset_detail, "rules", []) or []
                        seen_rule_ids: set[str] = set()
                        for rule in rules:
                            rule_id = getattr(rule, "id", "")
                            if rule_id in seen_rule_ids:
                                break
                            seen_rule_ids.add(rule_id)
                            try:
                                self.rules.append(
                                    CloudflareFirewallRule(
                                        id=rule_id,
                                        name=getattr(rule, "description", "")
                                        or rule_id,
                                        description=getattr(rule, "description", None),
                                        action=getattr(rule, "action", None),
                                        enabled=getattr(rule, "enabled", True),
                                        expression=getattr(rule, "expression", None),
                                        phase=ruleset_phase,
                                        zone=zone,
                                    )
                                )
                            except Exception as error:
                                logger.error(
                                    f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                                )
                    except Exception as error:
                        logger.error(
                            f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                        )
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
