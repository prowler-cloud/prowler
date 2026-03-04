from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_public_read_acl_disabled(Check):
    """Ensure object storage containers do not grant anonymous read access."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            acl_entries = [entry.strip() for entry in container.read_ACL.split(",")]
            if ".r:*" in acl_entries:
                report.status = "FAIL"
                report.status_extended = f"Container {container.name} has public read ACL (.r:*) allowing anonymous access."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Container {container.name} does not have public read ACL."
                )

            findings.append(report)

        return findings
