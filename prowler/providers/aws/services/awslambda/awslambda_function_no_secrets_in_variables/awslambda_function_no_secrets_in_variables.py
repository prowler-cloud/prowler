import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = awslambda_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(self.metadata())
            report.region = function.region
            report.resource_id = function.name
            report.resource_arn = function.arn
            report.resource_tags = function.tags

            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} variables."
            )

            if function.environment:
                detect_secrets_output = detect_secrets_scan(
                    data=json.dumps(function.environment, indent=2),
                    excluded_secrets=secrets_ignore_patterns,
                )
                if detect_secrets_output:
                    environment_variable_names = list(function.environment.keys())
                    secrets_string = ", ".join(
                        [
                            f"{secret['type']} in variable {environment_variable_names[int(secret['line_number']) - 2]}"
                            for secret in detect_secrets_output
                        ]
                    )
                    report.status = "FAIL"
                    report.status_extended = f"Potential secret found in Lambda function {function.name} variables -> {secrets_string}."

            findings.append(report)

        return findings
