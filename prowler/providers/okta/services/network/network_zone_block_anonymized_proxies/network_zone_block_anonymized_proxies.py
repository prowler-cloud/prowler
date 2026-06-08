from prowler.lib.check.models import Check, CheckReportOkta
from prowler.providers.okta.services.network.lib.network_zone_helpers import (
    compliant_anonymized_proxy_blocklist,
    missing_network_zone_scope_finding,
)
from prowler.providers.okta.services.network.network_zone_client import (
    network_zone_client,
)
from prowler.providers.okta.services.network.network_zone_service import (
    NetworkZoneSummary,
)


class network_zone_block_anonymized_proxies(Check):
    """Ensure Okta actively blocks anonymized proxy sources before auth."""

    def execute(self) -> list[CheckReportOkta]:
        """Evaluate whether an active blocklist covers anonymized proxies."""
        org_domain = network_zone_client.provider.identity.org_domain
        missing_scope = network_zone_client.missing_scope.get("network_zones")
        if missing_scope:
            return [
                missing_network_zone_scope_finding(
                    self.metadata(), org_domain, missing_scope
                )
            ]

        matching_zone, reason = compliant_anonymized_proxy_blocklist(
            network_zone_client.network_zones
        )

        resource = matching_zone or NetworkZoneSummary()
        report = CheckReportOkta(
            metadata=self.metadata(), resource=resource, org_domain=org_domain
        )
        if matching_zone:
            report.status = "PASS"
            report.status_extended = (
                f"Okta Network Zone {matching_zone.name} is an {reason}."
            )
        else:
            report.status = "FAIL"
            report.status_extended = (
                "No active Okta Network Zone blocklist was found that blocks "
                "anonymized proxies. Existing zones do not actively block gateway "
                "or proxy IPs, nor an Enhanced Dynamic Zone anonymizer category."
            )
        return [report]
