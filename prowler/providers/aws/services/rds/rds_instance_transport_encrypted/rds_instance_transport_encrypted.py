from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_transport_encrypted(Check):
    def execute(self):
        findings = []
        supported_engines = ["sqlserver", "postgres"]
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags
            report.status = "FAIL"
            report.status_extended = (
                f"RDS Instance {db_instance.id} connections are not encrypted."
            )
            # Check only RDS SQL Server or PostgreSQL engines (Aurora not supported)
            if (
                any(engine in db_instance.engine for engine in supported_engines)
                and "aurora" not in db_instance.engine
            ):
                for parameter in db_instance.parameters:
                    if (
                        parameter["ParameterName"] == "rds.force_ssl"
                        and parameter["ParameterValue"] == "1"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"RDS Instance {db_instance.id} connections use SSL encryption."

                findings.append(report)

        return findings
