from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.entra.entra_client import entra_client


class entra_conditional_access_trusted_named_location_exists(Check):
    """Check if at least one trusted IP-range named location is defined.

    Conditional Access named locations let an organization define trusted IP ranges.
    At least one IP-range named location should be marked as trusted and have at
    least one IP range defined.

    - PASS: A trusted IP-range named location with at least one IP range exists.
    - FAIL: No trusted IP-range named location with an IP range is defined.
    """

    def execute(self) -> List[CheckReportM365]:
        findings = []
        named_locations = entra_client.named_locations

        report = CheckReportM365(
            metadata=self.metadata(),
            resource=named_locations if named_locations else {},
            resource_name="Named Locations",
            resource_id="namedLocations",
        )
        report.status = "FAIL"
        report.status_extended = (
            "No trusted IP-range named location with at least one IP range is defined."
        )

        for location in named_locations:
            if (
                location.is_ip_location
                and location.is_trusted
                and location.ip_ranges_count >= 1
            ):
                report = CheckReportM365(
                    metadata=self.metadata(),
                    resource=location,
                    resource_name=location.display_name or "Named Location",
                    resource_id=location.id,
                )
                report.status = "PASS"
                report.status_extended = (
                    f"Trusted IP-range named location '{location.display_name or location.id}' "
                    f"is defined with {location.ip_ranges_count} IP range(s)."
                )
                break

        findings.append(report)
        return findings
