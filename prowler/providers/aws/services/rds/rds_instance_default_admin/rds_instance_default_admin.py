from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.rds.rds_client import rds_client


class rds_instance_default_admin(Check):
    def execute(self):
        findings = []
        for db_instance in rds_client.db_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags
            report.status = "FAIL"
            report.status_extended = (
                f"RDS Instance {db_instance.id} is using the default master username."
            )

            # Check only RDS DB instances that are not clustered
            if not db_instance.cluster_id:
                if (
                    db_instance.username != "admin"
                    and db_instance.username != "postgres"
                ):
                    report.status = "PASS"
                    report.status_extended = f"RDS Instance {db_instance.id} is not using the default master username."

                findings.append(report)

        for db_cluster in rds_client.db_clusters:
            report = Check_Report_AWS(self.metadata())
            report.region = rds_client.db_clusters[db_cluster].region
            report.resource_id = rds_client.db_clusters[db_cluster].id
            report.resource_arn = db_cluster
            report.resource_tags = rds_client.db_clusters[db_cluster].tags
            report.status = "FAIL"
            report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is using the default master username."
            if (
                rds_client.db_clusters[db_cluster].username != "admin"
                and rds_client.db_clusters[db_cluster].username != "postgres"
            ):
                report.status = "PASS"
                report.status_extended = f"RDS Cluster {rds_client.db_clusters[db_cluster].id} is not using the default master username."

            findings.append(report)

        return findings
