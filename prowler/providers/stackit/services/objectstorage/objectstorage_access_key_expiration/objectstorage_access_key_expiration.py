from prowler.lib.check.models import Check, CheckReportStackIT
from prowler.providers.stackit.services.objectstorage.objectstorage_client import (
    objectstorage_client,
)


class objectstorage_access_key_expiration(Check):
    def execute(self):
        findings = []
        for key in objectstorage_client.access_keys:
            report = CheckReportStackIT(
                metadata=self.metadata(),
                resource=key,
            )
            report.resource_id = key.key_id
            report.resource_name = key.display_name
            report.location = key.region

            if key.has_expiration():
                report.status = "PASS"
                report.status_extended = f"Access key {key.display_name} has an expiration date set ({key.expires})."
            else:
                report.status = "FAIL"
                report.status_extended = f"Access key {key.display_name} has no expiration date and never rotates."

            findings.append(report)
        return findings
