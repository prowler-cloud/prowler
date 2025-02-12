from prowler.lib.check.models import Check, Check_Report_NHN
from prowler.providers.nhn.services.compute.compute_client import compute_client


class compute_instance_login_user(Check):
    def execute(self):
        findings = []
        for instance in compute_client.instances:
            report = Check_Report_NHN(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"VM Instance {instance.name} has a appropriate login user."
            )
            if instance.login_user:
                report.status = "FAIL"
                report.status_extended = f"VM Instance {instance.name} has an Administrative(admin/root) login user."
            findings.append(report)

        return findings
