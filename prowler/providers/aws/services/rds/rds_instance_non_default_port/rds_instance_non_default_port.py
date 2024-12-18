from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_non_default_port(Check):
    def execute(self):
        findings = []
        default_ports = {
            3306: ["mysql", "mariadb", "aurora-mysql"],
            5432: ["postgres", "aurora-postgresql"],
            1521: ["oracle"],
            1433: ["sqlserver"],
            50000: ["db2"],
        }
        for db_instance_arn, db_instance in rds_client.db_instances.items():
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance_arn
            report.resource_tags = db_instance.tags
            report.status = "PASS"
            report.status_extended = (
                f"RDS Instance {db_instance.id} is not using the default port "
                f"{db_instance.port} for {db_instance.engine}."
            )
            if db_instance.port in default_ports:
                default_engines = default_ports[db_instance.port]
                for default_engine in default_engines:
                    if default_engine in db_instance.engine.lower():
                        report.status = "FAIL"
                        report.status_extended = (
                            f"RDS Instance {db_instance.id} is using the default port "
                            f"{db_instance.port} for {db_instance.engine}."
                        )

            findings.append(report)

        return findings
