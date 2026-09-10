from prowler.lib.check.models import Check, CheckReportE2eNetworks
from prowler.providers.e2enetworks.services.storage.storage_client import storage_client


class storage_efs_vpc_access_restricted(Check):
    """Check if E2E Networks EFS volumes restrict VPC access."""

    def execute(self) -> list[CheckReportE2eNetworks]:
        findings = []
        for volume in storage_client.efs_volumes:
            report = CheckReportE2eNetworks(metadata=self.metadata(), resource=volume)
            report.status = "PASS"
            report.status_extended = (
                f"EFS volume {volume.name} does not allow all VPC resources."
            )
            if volume.is_all_vpc_resources_allowed:
                report.status = "FAIL"
                report.status_extended = (
                    f"EFS volume {volume.name} allows access from all VPC resources."
                )
            findings.append(report)
        return findings
