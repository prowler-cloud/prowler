from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_listing_disabled(Check):
    """Ensure object storage container object listings are not publicly accessible."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            if ".rlistings" in container.read_ACL:
                report.status = "FAIL"
                report.status_extended = f"Container {container.name} has public listing enabled (.rlistings) allowing object enumeration."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Container {container.name} does not have public listing enabled."
                )

            findings.append(report)

        return findings
