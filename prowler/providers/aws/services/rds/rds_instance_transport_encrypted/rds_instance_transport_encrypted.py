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
            report.status = "FAIL"
            report.status_extended = (
                f"RDS Instance {db_instance.id} connections are not encrypted."
            )
            # Check only RDS SQL Server or PostgreSQL engines
            if any(engine in db_instance.engine for engine in supported_engines):
                for parameter in db_instance.parameters:
                    if (
                        parameter["ParameterName"] == "rds.force_ssl"
                        and parameter["ParameterValue"] == "1"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"RDS Instance {db_instance.id} connections use SSL encryption."

                findings.append(report)

        return findings
