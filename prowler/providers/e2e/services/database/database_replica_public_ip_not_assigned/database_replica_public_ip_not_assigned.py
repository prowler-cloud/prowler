from prowler.lib.check.models import Check, CheckReportE2e
from prowler.providers.e2e.services.database.database_client import database_client


class database_replica_public_ip_not_assigned(Check):
    """Check if E2E Cloud database read replicas do not have a public IP assigned."""

    def execute(self) -> list[CheckReportE2e]:
        findings = []
        for instance in database_client.instances:
            if instance.role != "replica":
                continue
            report = CheckReportE2e(metadata=self.metadata(), resource=instance)
            report.status = "PASS"
            report.status_extended = (
                f"Database replica {instance.name} does not have a public IP assigned."
            )
            if instance.has_public_ip:
                report.status = "FAIL"
                report.status_extended = (
                    f"Database replica {instance.name} has a public IP assigned."
                )
            findings.append(report)
        return findings
