from typing import Optional

from pydantic.v1 import BaseModel

from prowler.lib.logger import logger
from prowler.providers.cloudflare.lib.service.service import CloudflareService
from prowler.providers.cloudflare.models import CloudflareZone


class CloudflareWAFRuleset(BaseModel):
    """Represents a WAF ruleset (managed rules) for a zone."""

    id: str
    name: str
    kind: Optional[str] = None
    phase: Optional[str] = None
    enabled: bool = True
    zone: CloudflareZone

    class Config:
        arbitrary_types_allowed = True


class WAF(CloudflareService):
    """Collect WAF ruleset information for Cloudflare zones using rulesets API."""

    def __init__(self, provider):
        super().__init__(__class__.__name__, provider)
        self.rulesets: list[CloudflareWAFRuleset] = []
        self.__threading_call__(self._list_waf_rulesets)

    def _list_waf_rulesets(self, zone: CloudflareZone):
        """List WAF rulesets for a zone using the new rulesets API."""
        seen_ids: set[str] = set()
        try:
            for ruleset in self.client.rulesets.list(zone_id=zone.id):
                ruleset_id = getattr(ruleset, "id", "")
                if ruleset_id in seen_ids:
                    break
                seen_ids.add(ruleset_id)
                try:
                    self.rulesets.append(
                        CloudflareWAFRuleset(
                            id=ruleset_id,
                            name=getattr(ruleset, "name", ""),
                            kind=getattr(ruleset, "kind", None),
                            phase=getattr(ruleset, "phase", None),
                            enabled=True,
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
