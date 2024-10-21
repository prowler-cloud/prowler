from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.documentdb.documentdb_client import (
    documentdb_client,
)

class documentdb_instance_storage_encrypted(Check):
    def execute(self):
        findings = []
        # Iterate over all DocumentDB instances
        for db_instance in documentdb_client.db_instances.values():
            # Create a report for each instance
            report = Check_Report_AWS(self.metadata())
            report.region = db_instance.region
            report.resource_id = db_instance.id
            report.resource_arn = db_instance.arn
            report.resource_tags = db_instance.tags

            # Check if the instance is encrypted
            if db_instance.encrypted:
                report.status = "PASS"
                report.status_extended = (
                    f"DocumentDB Instance {db_instance.id} is encrypted."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"DocumentDB Instance {db_instance.id} is not encrypted."
                )

            findings.append(report)

        return findings
