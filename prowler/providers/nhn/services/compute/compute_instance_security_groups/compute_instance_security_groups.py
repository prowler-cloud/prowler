from prowler.lib.check.models import Check, CheckReportNHN
from prowler.providers.nhn.services.compute.compute_client import compute_client


class compute_instance_security_groups(Check):
    def execute(self):
        findings = []
        for instance in compute_client.instances:
            report = CheckReportNHN(
                metadata=self.metadata(),
                resource=instance,
            )
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} has a variety of security groups."
            )
            if instance.security_groups:
                report.status = "FAIL"
                report.status_extended = (
                    f"VM Instance {instance.name} has only the default security group."
                )
            findings.append(report)

        return findings
