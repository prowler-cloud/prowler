from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.ecs.ecs_client import ecs_client


class ecs_cluster_container_insights_enabled(Check):
    def execute(self):
        findings = []
        for cluster in ecs_client.clusters.values():
            report = Check_Report_AWS(self.metadata())
            report.region = cluster.region
            report.resource_id = cluster.name
            report.resource_arn = cluster.arn
            report.resource_tags = cluster.tags
            report.status = "FAIL"
            report.status_extended = (
                f"ECS cluster {cluster.name} does not have container insights enabled."
            )
            if cluster.settings:
                for setting in cluster.settings:
                    if (
                        setting["name"] == "containerInsights"
                        and setting["value"] == "enabled"
                    ):
                        report.status = "PASS"
                        report.status_extended = f"ECS cluster {cluster.name} has container insights enabled."
            findings.append(report)
        return findings
