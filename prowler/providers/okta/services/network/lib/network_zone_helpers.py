from prowler.lib.check.models import CheckReportOkta
from prowler.providers.okta.services.network.network_zone_service import (
    NetworkZoneSummary,
    OktaNetworkZone,
)

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
        if is_enhanced_dynamic_anonymizer_blocklist(zone):
            return zone, "active Enhanced Dynamic Zone blocklist for anonymizers"
    return None, ""


def static_ip_blocklist_evidence(
    network_zones: dict[str, OktaNetworkZone],
) -> OktaNetworkZone | None:
    """Return static IP blocklist evidence that requires human validation."""
    for zone in active_blocklist_zones(network_zones):
        if is_ip_blocklist_with_entries(zone):
            return zone
    return None


_SCOPE_ADVICE = (
    "Grant it on the Okta API Scopes tab of the service app in the Okta Admin "
    "Console, then re-run the check."
)


def missing_network_zone_scope_finding(
    metadata, org_domain: str, scope: str
) -> CheckReportOkta:
    """Build the MANUAL finding emitted when Network Zones cannot be listed."""
    resource = NetworkZoneSummary(
        id="network-zones-scope-missing",
        name="(scope not granted)",
    )
    report = CheckReportOkta(
        metadata=metadata, resource=resource, org_domain=org_domain
    )
    report.status = "MANUAL"
    report.status_extended = (
        f"Could not retrieve Okta Network Zones: the Okta service app "
        f"is missing the required `{scope}` API scope. {_SCOPE_ADVICE}"
    )
    return report
