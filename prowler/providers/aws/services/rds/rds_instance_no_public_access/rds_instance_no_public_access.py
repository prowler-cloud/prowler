from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_no_public_access(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags
            if not db_instance.public:
                report.status = "PASS"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is not publicly accessible."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"RDS Instance {db_instance.id} is set as publicly accessible."
                )
                # Check if restricted in DB Instance Security Group
                if db_instance.security_groups:
                    for security_group in ec2_client.security_groups:
                        if (
                            security_group.id in db_instance.security_groups
                            and not security_group.public_ports
                        ):
                            report.status = "PASS"
                            report.status_extended = f"RDS Instance {db_instance.id} is public but filtered with security groups."
            findings.append(report)

        return findings
