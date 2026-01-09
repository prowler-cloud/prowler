from datetime import datetime, timedelta, timezone

from prowler.lib.check.models import Check, CheckReportAlibabaCloud
from prowler.providers.alibabacloud.services.cs.cs_client import cs_client


class cs_kubernetes_cluster_check_weekly(Check):
    """Check if Cluster Check is triggered at least once per week for Kubernetes Clusters."""

    def execute(self) -> list[CheckReportAlibabaCloud]:
        findings = []

        # Get configurable max days from audit config (default: 7 days)
        max_cluster_check_days = cs_client.audit_config.get("max_cluster_check_days", 7)

        # Calculate the threshold date
        threshold_date = datetime.now(timezone.utc) - timedelta(
            days=max_cluster_check_days
        )

        for cluster in cs_client.clusters:
            report = CheckReportAlibabaCloud(metadata=self.metadata(), resource=cluster)
            report.region = cluster.region
            report.resource_id = cluster.id
            report.resource_arn = f"acs:cs:{cluster.region}:{cs_client.audited_account}:cluster/{cluster.id}"

            if cluster.last_check_time:
                # Ensure last_check_time is timezone-aware
                last_check = cluster.last_check_time
                if last_check.tzinfo is None:
                    # If naive datetime, assume UTC
                    last_check = last_check.replace(tzinfo=timezone.utc)

                # Calculate days since last check
                days_since_check = (datetime.now(timezone.utc) - last_check).days

                if last_check >= threshold_date:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Kubernetes cluster {cluster.name} has had a successful cluster check "
                        f"within the last {max_cluster_check_days} days "
                        f"(last check: {cluster.last_check_time.strftime('%Y-%m-%d %H:%M:%S UTC')}, "
                        f"{days_since_check} days ago)."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Kubernetes cluster {cluster.name} has not had a successful cluster check "
                        f"within the last {max_cluster_check_days} days "
                        f"(last check: {cluster.last_check_time.strftime('%Y-%m-%d %H:%M:%S UTC')}, "
                        f"{days_since_check} days ago)."
                    )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Kubernetes cluster {cluster.name} has no successful cluster check history. "
                    f"Cluster checks should be triggered at least once every {max_cluster_check_days} days."
                )

            findings.append(report)

        return findings
