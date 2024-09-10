from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ec2.ec2_client import ec2_client
from prowler.providers.aws.services.ec2.lib.security_groups import check_security_group
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_not_default_port(Check):
    def execute(self):
        findings = []
        default_ports = {
            "mysql": 3306,
            "mariadb": 3306,
            "aurora": 3306,
            "postgres": 5432,
            "oracle-se1": 1521,
            "oracle-se2": 1521,
            "oracle-ee": 1521,
            "sqlserver-ex": 1433,
            "sqlserver-web": 1433,
            "sqlserver-se": 1433,
            "sqlserver-ee": 1433,
        }

        for db_instance_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance_arn
            report.resource_tags = db_instance.tags

            if (
                db_instance.engine in default_ports
                and db_instance.port == default_ports[db_instance.engine]
            ):
                report.status = "FAIL"
                report.status_extended = f"RDS Instance {db_instance.id} is using the default port {db_instance.port} for {db_instance.engine}."
            else:
                port_allowed = False

                for (
                    security_group_arn,
                    security_group,
                ) in ec2_client.security_groups.items():
                    if security_group.id in db_instance.security_groups:
                        for ingress_rule in security_group.ingress_rules:
                            if check_security_group(
                                ingress_rule,
                                "tcp",
                                [db_instance.port],
                                any_address=True,
                            ):
                                port_allowed = True

                    if port_allowed:
                        report.status = "PASS"
                        report.status_extended = (
                            f"RDS Instance {db_instance.id} is using a non-default port ({db_instance.port}) for {db_instance.engine} "
                            f"and the security group {security_group.vpc_id} allows access on this port."
                        )
                        break

                if not port_allowed:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"RDS Instance {db_instance.id} is using a non-default port ({db_instance.port}) for {db_instance.engine}, "
                        "but none of the associated security groups allow access to this port."
                    )

            findings.append(report)

        return findings
