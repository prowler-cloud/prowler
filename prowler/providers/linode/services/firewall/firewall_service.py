from typing import List

from pydantic import BaseModel

from prowler.lib.logger import logger
from prowler.providers.linode.lib.service.service import LinodeService


class FirewallRule(BaseModel):
    """Model for a single firewall rule."""

    protocol: str = "TCP"
    ports: str = ""  # e.g. "22", "1-65535", ""
    addresses_ipv4: List[str] = []
    addresses_ipv6: List[str] = []
    action: str = "ACCEPT"  # ACCEPT or DROP
    label: str = ""


class Firewall(BaseModel):
    """Model for a Linode Cloud Firewall."""

    id: int
    label: str
    status: str
    inbound_rules: List[FirewallRule] = []
    outbound_rules: List[FirewallRule] = []
    tags: List[str] = []


class FirewallService(LinodeService):
    """Service to interact with Linode Cloud Firewalls."""

    firewalls: List[Firewall] = []

    def __init__(self, provider):
        super().__init__("firewall", provider)
        self._describe_firewalls()

    def _describe_firewalls(self):
        """Fetch all Linode Cloud Firewalls with their rules."""
        try:
            raw_firewalls = self.client.networking.firewalls()
            for fw in raw_firewalls:
                try:
                    inbound_rules = []
                    outbound_rules = []

                    try:
                        rules = fw.get_rules()
                        for rule in getattr(rules, "inbound", []) or []:
                            inbound_rules.append(
                                FirewallRule(
                                    protocol=getattr(rule, "protocol", "TCP").upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(
                                        getattr(rule, "addresses", None), "ipv4", []
                                    )
                                    or [],
                                    addresses_ipv6=getattr(
                                        getattr(rule, "addresses", None), "ipv6", []
                                    )
                                    or [],
                                    action=getattr(rule, "action", "ACCEPT").upper(),
                                    label=getattr(rule, "label", "") or "",
                                )
                            )
                        for rule in getattr(rules, "outbound", []) or []:
                            outbound_rules.append(
                                FirewallRule(
                                    protocol=getattr(rule, "protocol", "TCP").upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(
                                        getattr(rule, "addresses", None), "ipv4", []
                                    )
                                    or [],
                                    addresses_ipv6=getattr(
                                        getattr(rule, "addresses", None), "ipv6", []
                                    )
                                    or [],
                                    action=getattr(rule, "action", "ACCEPT").upper(),
                                    label=getattr(rule, "label", "") or "",
                                )
                            )
                    except Exception as error:
                        logger.warning(
                            f"firewall - Unable to fetch rules for firewall {fw.id}: {error}"
                        )

                    self.firewalls.append(
                        Firewall(
                            id=fw.id,
                            label=fw.label or f"firewall-{fw.id}",
                            status=fw.status or "unknown",
                            inbound_rules=inbound_rules,
                            outbound_rules=outbound_rules,
                            tags=fw.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"firewall - Error processing firewall {fw.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            logger.error(
                f"firewall - Error fetching firewalls: "
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
