from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_write_acl_restricted(Check):
    """Ensure object storage container write ACL does not allow all authenticated users."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            acl_entries = [entry.strip() for entry in container.write_ACL.split(",")]
            if "*:*" in acl_entries or "*" in acl_entries:
                report.status = "FAIL"
                report.status_extended = f"Container {container.name} has unrestricted write ACL allowing all authenticated users to write."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Container {container.name} has restricted write ACL."
                )

            findings.append(report)

        return findings
