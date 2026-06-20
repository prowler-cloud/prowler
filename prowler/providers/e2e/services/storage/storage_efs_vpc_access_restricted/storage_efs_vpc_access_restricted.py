from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.storage.storage_client import storage_client


class storage_efs_vpc_access_restricted(Check):
    def execute(self):
        findings = []
        for volume in storage_client.efs_volumes:
            report = CheckReportE2e(metadata=self.metadata(), resource=volume)
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
