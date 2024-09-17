from packaging import version

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_redis_replication_group_auth_enabled(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = repl_group.region
            report.resource_id = repl_group.id
            report.resource_arn = repl_group.arn
            report.resource_tags = repl_group.tags

            for cluster in repl_group.member_clusters:
                if version.parse(cluster.engine_version) < version.parse("6.0"):
                    if not cluster.auth_token_enabled:
                        report.status = "FAIL"
                        report.status_extended = f"Elasticache Redis replication group {repl_group.id}(v{cluster.engine_version}) does not have AUTH enabled."

                    else:
                        report.status = "PASS"
                        report.status_extended = f"Elasticache Redis replication group {repl_group.id}(v{cluster.engine_version}) does have AUTH enabled."
                else:
                    report.status = "MANUAL"
                    report.status_extended = f"Elasticache Redis replication group {repl_group.id}(v{cluster.engine_version}) does not have to use AUTH, but it should have Redis ACL configured."

            findings.append(report)

        return findings
