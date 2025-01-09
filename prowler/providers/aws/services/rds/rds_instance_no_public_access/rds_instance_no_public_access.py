from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.rds.rds_client import rds_client
from prowler.providers.aws.services.vpc.vpc_client import vpc_client


class rds_instance_no_public_access(Check):
    def execute(self):
        findings = []
        for db_instance_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance_arn
            report.resource_tags = db_instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"RDS Instance {db_instance.id} is not publicly accessible."
            )
            if db_instance.public:
                report.status_extended = f"RDS Instance {db_instance.id} is set as publicly accessible, but is not publicly exposed."
                # Check if any DB Instance Security Group is publicly open
                if db_instance.security_groups:
                    public_sg = False
                    report.status_extended = f"RDS Instance {db_instance.id} is set as publicly accessible but filtered with security groups."
                    db_instance_port = db_instance.endpoint.get("Port")
                    if db_instance_port:
                        for security_group in ec2_client.security_groups.values():
                            if security_group.id in db_instance.security_groups:
                                for ingress_rule in security_group.ingress_rules:
                                    if check_security_group(
                                        ingress_rule,
                                        "tcp",
                                        [db_instance_port],
                                        any_address=True,
                                    ):
                                        report.status_extended = f"RDS Instance {db_instance.id} is set as publicly accessible and security group {security_group.name} ({security_group.id}) has {db_instance.engine} port {db_instance_port} open to the Internet at endpoint {db_instance.endpoint.get('Address')} but is not in a public subnet."
                                        public_sg = True
                                        if db_instance.subnet_ids:
                                            for subnet_id in db_instance.subnet_ids:
                                                if (
                                                    subnet_id in vpc_client.vpc_subnets
                                                    and vpc_client.vpc_subnets[
                                                        subnet_id
                                                    ].public
                                                ):
                                                    report.status = "FAIL"
                                                    report.status_extended = f"RDS Instance {db_instance.id} is set as publicly accessible and security group {security_group.name} ({security_group.id}) has {db_instance.engine} port {db_instance_port} open to the Internet at endpoint {db_instance.endpoint.get('Address')} in a public subnet {subnet_id}."
                                                    break
                                    if public_sg:
                                        break
                            if public_sg:
                                break

            findings.append(report)

        return findings
