from typing import List

from prowler.lib.check.models import Check, CheckReportOpenStack
from prowler.providers.openstack.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_container_acl_not_globally_shared(Check):
    """Ensure object storage container read ACL does not use global sharing."""

    def execute(self) -> List[CheckReportOpenStack]:
        findings: List[CheckReportOpenStack] = []

        for container in objectstorage_client.containers:
            report = CheckReportOpenStack(metadata=self.metadata(), resource=container)
            acl_entries = [entry.strip() for entry in container.read_ACL.split(",")]
            if "*:*" in acl_entries or "*" in acl_entries:
                report.status = "FAIL"
                report.status_extended = f"Container {container.name} has globally shared read ACL (*:*) allowing all authenticated users from any project."
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Container {container.name} read ACL is not globally shared."
                )

            findings.append(report)

        return findings
