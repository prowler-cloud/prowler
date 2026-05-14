from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_versioning_enabled(Check):
    """Ensure object storage containers have versioning enabled for data protection."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            if container.versioning_enabled:
                report.status = "PASS"
                location = container.versions_location or container.history_location
                mode = "versions" if container.versions_location else "history"
                report.status_extended = f"Container {container.name} has versioning enabled ({mode} location: {location})."
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Container {container.name} does not have versioning enabled."
                )

            findings.append(report)

        return findings
