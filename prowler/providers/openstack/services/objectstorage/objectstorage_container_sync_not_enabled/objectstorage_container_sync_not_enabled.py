from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_sync_not_enabled(Check):
    """Ensure object storage containers do not have container sync configured."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            if container.sync_to:
                report.status = "FAIL"
                report.status_extended = f"Container {container.name} has container sync enabled (sync target: {container.sync_to})."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Container {container.name} does not have container sync enabled."
                )

            findings.append(report)

        return findings
