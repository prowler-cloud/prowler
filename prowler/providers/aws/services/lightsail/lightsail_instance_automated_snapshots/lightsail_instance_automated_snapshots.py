from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_instance_automated_snapshots(Check):
    def execute(self):
        findings = []
        for instance in lightsail_client.instances.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
            report.status = "FAIL"
            report.status_extended = (
                f"Instance '{instance.name}' does not have automated snapshots enabled."
            )

            if instance.auto_snapshot:
                report.status = "PASS"
                report.status_extended = (
                    f"Instance '{instance.name}' has automated snapshots enabled."
                )

            findings.append(report)

        return findings
