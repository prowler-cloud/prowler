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

            if version.parse(repl_group.engine_version) < version.parse("6.0"):
                if not repl_group.auth_token_enabled:
                    report.status = "FAIL"
                    report.status_extended = f"Elasticache Redis replication group {repl_group.id}(v{repl_group.engine_version}) does not have AUTH enabled."

                else:
                    report.status = "PASS"
                    report.status_extended = f"Elasticache Redis replication group {repl_group.id}(v{repl_group.engine_version}) does have AUTH enabled."
            else:
                report.status = "MANUAL"
                report.status_extended = f"Elasticache Redis replication group {repl_group.id} has version {repl_group.engine_version} which supports Redis ACLs. Please review the ACL configuration."

            findings.append(report)

        return findings
