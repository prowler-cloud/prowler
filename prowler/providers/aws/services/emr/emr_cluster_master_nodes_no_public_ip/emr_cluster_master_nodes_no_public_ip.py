from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.emr.emr_client import emr_client
from prowler.providers.aws.services.emr.emr_service import ClusterStatus


class emr_cluster_master_nodes_no_public_ip(Check):
    def execute(self):
        findings = []
        for cluster in emr_client.clusters.values():
            if cluster.status not in (
                ClusterStatus.TERMINATED,
                ClusterStatus.TERMINATED_WITH_ERRORS,
            ):
                report = Check_Report_AWS(self.metadata())
                report.region = cluster.region
                report.resource_id = cluster.id
                report.resource_arn = cluster.arn

                if cluster.public:
                    report.status = "FAIL"
                    report.status_extended = f"EMR Cluster {cluster.id} has a Public IP"
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"EMR Cluster {cluster.id} has not a Public IP"
                    )

                findings.append(report)

        return findings
