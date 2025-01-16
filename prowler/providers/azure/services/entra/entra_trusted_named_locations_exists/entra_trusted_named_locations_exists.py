from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_trusted_named_locations_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        for tenant, named_locations in entra_client.named_locations.items():
            report = Check_Report_Azure(
                metadata=self.metadata(), resource_metadata=named_locations
            )
            report.status = "FAIL"
            report.subscription = f"Tenant: {tenant}"
            report.resource_name = "Named Locations"
            report.resource_id = "Named Locations"
            report.status_extended = (
                "There is no trusted location with IP ranges defined."
            )
            for named_location in named_locations.values():
                if named_location.ip_ranges_addresses and named_location.is_trusted:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource_metadata=named_location
                    )
                    report.subscription = f"Tenant: {tenant}"
                    report.status = "PASS"
                    report.status_extended = f"Exits trusted location with trusted IP ranges, this IPs ranges are: {[ip_range for ip_range in named_location.ip_ranges_addresses if ip_range]}"
                    break

            findings.append(report)

        return findings
