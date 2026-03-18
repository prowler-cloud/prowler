import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_etl_jobs_no_secrets_in_arguments(Check):
    """Check if Glue ETL jobs have secrets in their default arguments.

    Scans the DefaultArguments of each Glue job for hardcoded credentials,
    tokens, passwords, and other sensitive values that should be stored in
    Secrets Manager or Parameter Store instead.
    """

    def execute(self):
        findings = []
        secrets_ignore_patterns = glue_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for job in glue_client.jobs:
            report = Check_Report_AWS(metadata=self.metadata(), resource=job)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Glue job {job.name} default arguments."
            )

            if job.arguments:
                detect_secrets_output = detect_secrets_scan(
                    data=json.dumps(job.arguments),
                    excluded_secrets=secrets_ignore_patterns,
                    detect_secrets_plugins=glue_client.audit_config.get(
                        "detect_secrets_plugins",
                    ),
                )
                if detect_secrets_output:
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} on line {secret['line_number']}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secrets found in Glue job {job.name} default arguments -> {secrets_string}."

            findings.append(report)

        return findings
