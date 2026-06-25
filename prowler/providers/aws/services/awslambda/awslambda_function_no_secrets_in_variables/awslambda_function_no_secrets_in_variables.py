import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import annotate_verified_secrets, detect_secrets_scan
from prowler.providers.aws.services.awslambda.awslambda_client import awslambda_client


class awslambda_function_no_secrets_in_variables(Check):
    def execute(self):
        findings = []
        secrets_ignore_patterns = awslambda_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for function in awslambda_client.functions.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=function)

            report.status = "PASS"
            report.status_extended = (
                f"No secrets found in Lambda function {function.name} variables."
            )

            if function.environment:
                detect_secrets_output = detect_secrets_scan(
                    data=json.dumps(function.environment, indent=2),
                    excluded_secrets=secrets_ignore_patterns,
                    validate=awslambda_client.audit_config.get(
                        "secrets_validate", False
                    ),
                )
                original_env_vars = []
                for name, value in function.environment.items():
                    original_env_vars.append(name)
                if detect_secrets_output:
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
