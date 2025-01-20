from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_cluster_non_default_port(Check):
    def execute(self):
        findings = []
        default_ports = {
            3306: ["mysql", "mariadb", "aurora-mysql"],
            5432: ["postgres", "aurora-postgresql"],
            1521: ["oracle"],
            1433: ["sqlserver"],
            50000: ["db2"],
        }
        for db_cluster in rds_client.db_clusters.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=db_cluster)
            report.status = "PASS"
            report.status_extended = (
                f"RDS Cluster {db_cluster.id} is not using the default port "
                f"{db_cluster.port} for {db_cluster.engine}."
            )
            if db_cluster.port in default_ports:
                default_engines = default_ports[db_cluster.port]
                for default_engine in default_engines:
                    if default_engine in db_cluster.engine.lower():
                        report.status = "FAIL"
                        report.status_extended = (
                            f"RDS Cluster {db_cluster.id} is using the default port "
                            f"{db_cluster.port} for {db_cluster.engine}."
                        )

            findings.append(report)

        return findings
