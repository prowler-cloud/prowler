from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client


class ec2_instance_paravirtual_type(Check):
    def execute(self):
        findings = []
        for instance in ec2_client.instances:
            if instance.state != "terminated":
                report = Check_Report_AWS(metadata=self.metadata(), resource=instance)
                report.status = "PASS"
                report.status_extended = (
                    f"EC2 Instance {instance.id} virtualization type is set to HVM."
                )
                if instance.virtualization_type == "paravirtual":
                    report.status = "FAIL"
                    report.status_extended = f"EC2 Instance {instance.id} virtualization type is set to paravirtual."

                findings.append(report)

        return findings
