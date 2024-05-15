from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.lightsail.lightsail_client import lightsail_client


class lightsail_database_public(Check):
    def execute(self):
        findings = []

        for arn_database, database in lightsail_client.databases.items():
            report = Check_Report_AWS(self.metadata())
            report.region = database.region
            report.resource_id = database.id
            report.resource_arn = arn_database
            report.resource_tags = database.tags
            report.status = "FAIL"
            report.status_extended = f"Database '{database.name}' is public."

            if not database.public_access:
                report.status = "PASS"
                report.status_extended = f"Database '{database.name}' is not public."

            findings.append(report)

        return findings
