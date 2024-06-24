from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.elasticache.elasticache_client import (
    elasticache_client,
)


class elasticache_replication_group_encrypted_in_transit(Check):
    def execute(self):
        findings = []
        for repl_group in elasticache_client.replication_groups.values():
            report = Check_Report_AWS(self.metadata())
            report.region = repl_group.region
            report.resource_id = repl_group.id
            report.resource_arn = repl_group.arn
            report.status = "FAIL"
            report.status_extended = f"Elasticache Replication Group {repl_group.id} does not have in transit encryption enabled."
            if repl_group.transit_encryption:
                report.status = "PASS"
                report.status_extended = f"Elasticache Replication Group {repl_group.id} has in transit encryption enabled."

            findings.append(report)

        return findings
