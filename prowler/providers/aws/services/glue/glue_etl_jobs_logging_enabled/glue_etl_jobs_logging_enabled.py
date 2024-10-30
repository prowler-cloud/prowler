from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_etl_jobs_logging_enabled(Check):
    """Check if Glue ETL jobs have logging enabled.

    This check will return FAIL if the Glue ETL job does not have logging enabled.
    """

    def execute(self) -> List[Check_Report_AWS]:
        """Execute the Glue ETL jobs logging enabled check.

        Iterate over all Glue ETL jobs and check if they have logging enabled.

        Returns:
            List[Check_Report_AWS]: A list of report objects with the results of the check.
        """
        findings = []
        for job in glue_client.jobs:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = job.name
            report.resource_arn = job.arn
            report.region = job.region
            report.resource_tags = job.tags
            report.status = "FAIL"
            report.status_extended = (
                f"Glue job {job.name} does not have logging enabled."
            )

            if (
                job.arguments.get("--enable-continuous-cloudwatch-log", "false")
                == "true"
            ):
                report.status = "PASS"
                report.status_extended = f"Glue job {job.name} have logging enabled."

            findings.append(report)

        return findings
