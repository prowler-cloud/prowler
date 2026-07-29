import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = awslambda_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        validate = awslambda_client.audit_config.get("secrets_validate", False)
        functions = list(awslambda_client.functions.values())

        # Scan every function's environment variables in batched Kingfisher
        # invocations instead of one subprocess per function. Payloads are
        # yielded lazily so only a chunk is held/written at a time, which matters
        # for accounts with very large numbers of Lambda functions.
        def environment_payloads():
            for index, function in enumerate(functions):
                if function.environment:
                    yield index, json.dumps(function.environment, indent=2)

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                environment_payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for index, function in enumerate(functions):
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} variables."
            )

            if function.environment:
                if scan_error:
                    report.status = "MANUAL"
                    report.status_extended = (
                        f"Could not scan Lambda function {function.name} variables "
                        f"for secrets: {scan_error}; manual review is required."
                    )
                    findings.append(report)
                    continue
                detect_secrets_output = batch_results.get(index)
                if detect_secrets_output:
                    original_env_vars = list(function.environment.keys())
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in variable {original_env_vars[secret['line_number'] - 2]}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in Lambda function {function.name} variables -> {secrets_string}."
                    annotate_verified_secrets(report, detect_secrets_output)

            findings.append(report)

        return findings
