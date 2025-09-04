from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.services.clusters.clusters_client import (
    clusters_client,
)


class clusters_tls_enabled(Check):
    """Check if MongoDB Atlas clusters have TLS authentication required

    This class verifies that MongoDB Atlas clusters have TLS authentication
    required to secure data in transit.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas cluster TLS enabled check

        Iterates over all clusters and checks if they have TLS
        enabled (sslEnabled=true).

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each cluster
        """
        findings = []

        for cluster in clusters_client.clusters.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=cluster)

            if cluster.ssl_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Cluster {cluster.name} in project {cluster.project_name} "
                    f"has TLS authentication enabled."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Cluster {cluster.name} in project {cluster.project_name} "
                    f"does not have TLS authentication enabled."
                )

            findings.append(report)

        return findings
