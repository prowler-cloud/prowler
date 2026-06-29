import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
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
        validate = glue_client.audit_config.get("secrets_validate", False)
        jobs = list(glue_client.jobs)

        # Collect every default argument across all jobs and scan them in batched
        # Kingfisher invocations instead of one subprocess per argument. Findings
        # are keyed by (job index, argument name).
        def payloads():
            for job_index, job in enumerate(jobs):
                if job.arguments:
                    for arg_name, arg_value in job.arguments.items():
                        yield (job_index, arg_name), json.dumps({arg_name: arg_value})

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(), excluded_secrets=secrets_ignore_patterns, validate=validate
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for job_index, job in enumerate(jobs):
            report = Check_Report_AWS(metadata=self.metadata(), resource=job)
            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Glue job {job.name} default arguments."
            )

            if job.arguments and scan_error:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Could not scan Glue job {job.name} default arguments for "
                    f"secrets: {scan_error}; manual review is required."
                )
                findings.append(report)
                continue

            if job.arguments:
                secrets_found = []
                all_secrets = []
                for arg_name in job.arguments:
                    detect_secrets_output = batch_results.get((job_index, arg_name))
                    if detect_secrets_output:
                        all_secrets.extend(detect_secrets_output)
                        secrets_found.extend(
                            [
                                f"{secret['type']} in argument {arg_name}"
                                for secret in detect_secrets_output
                            ]
                        )

                if secrets_found:
                    report.status = "FAIL"
                    report.status_extended = f"Potential secrets found in Glue job {job.name} default arguments: {', '.join(secrets_found)}."
                    annotate_verified_secrets(report, all_secrets)

            findings.append(report)

        return findings
