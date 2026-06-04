from prowler.providers.okta.services.network.network_zone_service import OktaNetworkZone

ANONYMIZER_CATEGORY_MARKERS = (
    "ANONYM",
    "PROXY",
    "TOR",
    "VPN",
)


def active_blocklist_zones(
    network_zones: dict[str, OktaNetworkZone],
) -> list[OktaNetworkZone]:
    """Return active Network Zones configured for blocklist usage."""
    return sorted(
        [
            zone
            for zone in network_zones.values()
            if zone.status.upper() == "ACTIVE" and zone.usage.upper() == "BLOCKLIST"
        ],
        key=lambda zone: (zone.name, zone.id),
    )


def is_ip_blocklist_with_entries(zone: OktaNetworkZone) -> bool:
    """Return True when an IP blocklist zone contains gateway/proxy entries."""
    return zone.type.upper() == "IP" and bool(zone.gateways or zone.proxies)


def is_enhanced_dynamic_anonymizer_blocklist(zone: OktaNetworkZone) -> bool:
    """Return True for active Enhanced Dynamic blocklists covering anonymizers."""
    if zone.type.upper() != "DYNAMIC_V2":
        return False
    if zone.system and zone.name == "DefaultEnhancedDynamicZone":
        return True
    categories = [category.upper() for category in zone.ip_service_categories]
    return any(
        marker in category
        for category in categories
        for marker in ANONYMIZER_CATEGORY_MARKERS
    )


def compliant_anonymized_proxy_blocklist(
    network_zones: dict[str, OktaNetworkZone],
) -> tuple[OktaNetworkZone | None, str]:
    """Find the Network Zone that satisfies anonymized-proxy blocklisting."""
    for zone in active_blocklist_zones(network_zones):
        if is_ip_blocklist_with_entries(zone):
            return zone, "active IP blocklist with gateway or proxy IP entries"
        if is_enhanced_dynamic_anonymizer_blocklist(zone):
            return zone, "active Enhanced Dynamic Zone blocklist for anonymizers"
    return None, ""
