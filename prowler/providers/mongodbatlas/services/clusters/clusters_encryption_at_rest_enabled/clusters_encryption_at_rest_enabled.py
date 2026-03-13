from typing import List

from prowler.lib.check.models import Check, CheckReportMongoDBAtlas
from prowler.providers.mongodbatlas.config import ATLAS_ENCRYPTION_PROVIDERS
from prowler.providers.mongodbatlas.services.clusters.clusters_client import (
    clusters_client,
)


class clusters_encryption_at_rest_enabled(Check):
    """Check if MongoDB Atlas clusters have encryption at rest enabled

    This class verifies that MongoDB Atlas clusters have encryption at rest
    enabled to protect data stored on disk.
    """

    def execute(self) -> List[CheckReportMongoDBAtlas]:
        """Execute the MongoDB Atlas cluster encryption at rest check

        Iterates over all clusters and checks if they have encryption at rest
        enabled with a supported encryption provider.

        Returns:
            List[CheckReportMongoDBAtlas]: A list of reports for each cluster
        """
        findings = []

        for cluster in clusters_client.clusters.values():
            report = CheckReportMongoDBAtlas(metadata=self.metadata(), resource=cluster)

            if cluster.encryption_at_rest_provider:
                if cluster.encryption_at_rest_provider in ATLAS_ENCRYPTION_PROVIDERS:
                    if cluster.encryption_at_rest_provider == "NONE":
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Cluster {cluster.name} in project {cluster.project_name} "
                            f"has encryption at rest explicitly disabled."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"Cluster {cluster.name} in project {cluster.project_name} "
                            f"has encryption at rest enabled with provider: {cluster.encryption_at_rest_provider}."
                        )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Cluster {cluster.name} in project {cluster.project_name} "
                        f"has an unsupported encryption provider: {cluster.encryption_at_rest_provider}."
                    )
            else:
                # Check provider settings for EBS encryption (AWS specific)
                provider_settings = cluster.provider_settings or {}
                encrypt_ebs_volume = provider_settings.get("encryptEBSVolume", False)

                if encrypt_ebs_volume:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Cluster {cluster.name} in project {cluster.project_name} "
                        f"has EBS volume encryption enabled."
                    )
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Cluster {cluster.name} in project {cluster.project_name} "
                        f"does not have encryption at rest enabled."
                    )

            findings.append(report)

        return findings
