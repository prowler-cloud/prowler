from typing import List, Optional

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
    # None means the device count could not be determined (fetch failed), as
    # opposed to 0 which means the firewall genuinely has no devices attached.
    attached_devices_count: Optional[int] = None
    tags: List[str] = []


class FirewallService(LinodeService):
    """Service to interact with Linode Cloud Firewalls."""

    def __init__(self, provider):
        super().__init__("firewall", provider)
        self.firewalls: List[Firewall] = []
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
                    attached_devices_count = None

                    try:
                        attached_devices_count = len(fw.devices)
                    except Exception as error:
                        logger.warning(
                            f"firewall - Unable to fetch devices for firewall {fw.id}: {error}"
                        )

                    try:
                        # linode_api4 Firewall objects expose rules as a mapped object.
                        rules = fw.rules
                        inbound_policy = getattr(rules, "inbound_policy", "")
                        outbound_policy = getattr(rules, "outbound_policy", "")
                        inbound = getattr(rules, "inbound", [])
                        outbound = getattr(rules, "outbound", [])

                        for rule in inbound:
                            addresses = getattr(rule, "addresses", None)
                            inbound_rules.append(
                                FirewallRule(
                                    protocol=(
                                        getattr(rule, "protocol", None) or "TCP"
                                    ).upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(addresses, "ipv4", []) or [],
                                    addresses_ipv6=getattr(addresses, "ipv6", []) or [],
                                    action=(
                                        getattr(rule, "action", None) or "ACCEPT"
                                    ).upper(),
                                    label=getattr(rule, "label", "") or "",
                                )
                            )
                        for rule in outbound:
                            addresses = getattr(rule, "addresses", None)
                            outbound_rules.append(
                                FirewallRule(
                                    protocol=(
                                        getattr(rule, "protocol", None) or "TCP"
                                    ).upper(),
                                    ports=getattr(rule, "ports", "") or "",
                                    addresses_ipv4=getattr(addresses, "ipv4", []) or [],
                                    addresses_ipv6=getattr(addresses, "ipv6", []) or [],
                                    action=(
                                        getattr(rule, "action", None) or "ACCEPT"
                                    ).upper(),
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
                            inbound_policy=inbound_policy,
                            outbound_policy=outbound_policy,
                            attached_devices_count=attached_devices_count,
                            tags=fw.tags or [],
                        )
                    )
                except Exception as error:
                    logger.error(
                        f"firewall - Error processing firewall {fw.id}: "
                        f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
                    )
        except Exception as error:
            self._log_fetch_error("firewalls", "firewall:read_only", error)
