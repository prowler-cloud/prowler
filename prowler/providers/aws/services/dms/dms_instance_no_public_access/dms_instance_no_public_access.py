from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.dms.dms_client import dms_client
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group


class dms_instance_no_public_access(Check):
    def execute(self):
        findings = []
        for instance in dms_client.instances:
            report = Check_Report_AWS(self.metadata())
            report.region = instance.region
            report.resource_id = instance.id
            report.resource_arn = instance.arn
            report.resource_tags = instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"DMS Replication Instance {instance.id} is not publicly accessible."
            )
            if instance.public:
                report.status_extended = f"DMS Replication Instance {instance.id} is set as publicly accessible, but is not publicly exposed."
                # Check if any DB Instance Security Group is publicly open
                if instance.security_groups:
                    report.status = "PASS"
                    report.status_extended = f"DMS Replication Instance {instance.id} is set as publicly accessible but filtered with security groups."
                    for security_group in ec2_client.security_groups.values():
                        if security_group.id in instance.security_groups:
                            for ingress_rule in security_group.ingress_rules:
                                if check_security_group(
                                    ingress_rule,
                                    "-1",
                                    ports=None,
                                    any_address=True,
                                ):
                                    report.status = "FAIL"
                                    report.status_extended = f"DMS Replication Instance {instance.id} is set as publicly accessible and security group {security_group.name} ({security_group.id}) is open to the Internet."
                                    break
            findings.append(report)

        return findings
