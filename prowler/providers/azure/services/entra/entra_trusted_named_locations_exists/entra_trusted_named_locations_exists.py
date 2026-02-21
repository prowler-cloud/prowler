from prowler.lib.check.models import Check, Check_Report_Azure
from prowler.providers.azure.services.entra.entra_client import entra_client


class entra_trusted_named_locations_exists(Check):
    def execute(self) -> Check_Report_Azure:
        findings = []

        tenant_id = entra_client.tenant_ids[0]

        for tenant_domain, named_locations in entra_client.named_locations.items():
            trusted_location_found = False
            for named_location in named_locations.values():
                if named_location.ip_ranges_addresses and named_location.is_trusted:
                    report = Check_Report_Azure(
                        metadata=self.metadata(), resource=named_location
                    )
                    report.subscription = f"Tenant: {tenant_domain}"
                    report.status = "PASS"
                    report.status_extended = f"Trusted location {named_location.name} exists with trusted IP ranges: {[ip_range for ip_range in named_location.ip_ranges_addresses if ip_range]}"
                    findings.append(report)
                    trusted_location_found = True

            if not trusted_location_found:
                report = Check_Report_Azure(metadata=self.metadata(), resource={})
                report.status = "FAIL"
                report.subscription = f"Tenant: {tenant_domain}"
                report.resource_name = tenant_domain
                report.resource_id = tenant_id
                report.status_extended = (
                    "There is no trusted location with IP ranges defined."
                )
                findings.append(report)

        return findings
