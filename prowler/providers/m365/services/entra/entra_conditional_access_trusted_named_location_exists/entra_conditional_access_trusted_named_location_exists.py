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

    def execute(self) -> list[CheckReportM365]:
        """Execute the trusted named location check.

        Returns:
            A list containing the trusted named location evaluation report.
        """
        findings = []
        for location in entra_client.named_locations:
            location_name = location.display_name or location.id
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=location,
                resource_name=location.display_name or "Named Location",
                resource_id=location.id,
            )
            report.status = "FAIL"
            report.status_extended = f"Named location '{location_name}' is not a trusted IP-range location with at least one IP range."

            if (
                location.is_ip_location
                and location.is_trusted
                and location.ip_ranges_count >= 1
            ):
                report.status = "PASS"
                report.status_extended = (
                    f"Trusted IP-range named location '{location_name}' "
                    f"is defined with {location.ip_ranges_count} IP range(s)."
                )

            findings.append(report)
        return findings
