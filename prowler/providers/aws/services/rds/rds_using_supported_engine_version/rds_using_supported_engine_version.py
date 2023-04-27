from prowler.config.config import get_config_var
from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_using_supported_engine_version(Check):
    def execute(self):
        findings = []
        for db_engines in rds_client.db_engines:
            report = Check_Report_AWS(self.metadata())
            report.region = db_engines.region
            report.status = "FAIL"
            report.status_extended = (
                f"RDS Engine version {db_engines.engine_version} is deprecated."
            )
            # Check only depending on the engine

            if db_engines.engine == "mysql":
                if db_engines.engine_version in get_config_var("supported_rds_engines_mysql"):
                    report.status = "PASS"
                    report.status_extended = f"RDS Engine version {db_engines.engine_version} is deprecated."
            elif db_engines.engine == "mariadb":
                if db_engines.engine_version in get_config_var("supported_rds_engines_mariadb"):
                    report.status = "PASS"
                    report.status_extended = f"RDS Engine version {db_engines.engine_version} is deprecated."
            elif db_engines.engine == "postgres":
                if db_engines.engine_version in get_config_var("supported_rds_engines_postgres"):
                    report.status = "PASS"
                    report.status_extended = f"RDS Engine version {db_engines.engine_version} is deprecated."
            else:
                report.status = "PASS"
                report.status_extended = f"RDS Engine {db_engines.engine} is not supported for this check."

            findings.append(report)

        return findings
