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
    inbound_policy: str
    outbound_policy: str
    attached_devices_count: int
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
                    inbound_policy = ""
                    outbound_policy = ""
                    entities = []

                    try:
                        # linode_api4 Firewall objects expose rules as a mapped object.
                        rules = fw.rules
                        inbound_policy = getattr(rules, "inbound_policy", "")
                        outbound_policy = getattr(rules, "outbound_policy", "")
                        inbound = getattr(rules, "inbound", [])
                        outbound = getattr(rules, "outbound", [])

                        entities = fw.devices
                        for rule in inbound:
                            addresses = getattr(rule, "addresses", None)
                            inbound_rules.append(
                                FirewallRule(
                                    protocol=getattr(rule, "protocol", "TCP").upper(),
                                    ports=getattr(rule, "ports", ""),
                                    addresses_ipv4=getattr(addresses, "ipv4", []),
                                    addresses_ipv6=getattr(addresses, "ipv6", []),
                                    action=getattr(rule, "action", "ACCEPT").upper(),
                                    label=getattr(rule, "label", ""),
                                )
                            )
                        for rule in outbound:
                            addresses = getattr(rule, "addresses", None)
                            outbound_rules.append(
                                FirewallRule(
                                    protocol=getattr(rule, "protocol", "TCP").upper(),
                                    ports=getattr(rule, "ports", ""),
                                    addresses_ipv4=getattr(addresses, "ipv4", []),
                                    addresses_ipv6=getattr(addresses, "ipv6", []),
                                    action=getattr(rule, "action", "ACCEPT").upper(),
                                    label=getattr(rule, "label", ""),
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
                            inbound_policy=inbound_policy,
                            outbound_policy=outbound_policy,
                            attached_devices_count=len(entities),
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
