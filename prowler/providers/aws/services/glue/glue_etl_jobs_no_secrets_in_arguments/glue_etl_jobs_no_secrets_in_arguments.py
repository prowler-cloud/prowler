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
                secrets_found = []
                for arg_name, arg_value in job.arguments.items():
                    detect_secrets_output = detect_secrets_scan(
                        data=json.dumps({arg_name: arg_value}),
                        excluded_secrets=secrets_ignore_patterns,
                        detect_secrets_plugins=glue_client.audit_config.get(
                            "detect_secrets_plugins",
                        ),
                    )
                    if detect_secrets_output:
                        secrets_found.extend(
                            [
                                f"{secret['type']} in argument {arg_name}"
                                for secret in detect_secrets_output
                            ]
                        )

                if secrets_found:
                    report.status = "FAIL"
                    report.status_extended = f"Potential secrets found in Glue job {job.name} default arguments: {', '.join(secrets_found)}."

            findings.append(report)

        return findings
