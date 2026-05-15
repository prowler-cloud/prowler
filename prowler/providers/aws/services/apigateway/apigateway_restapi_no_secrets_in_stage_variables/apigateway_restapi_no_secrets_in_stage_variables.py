import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import detect_secrets_scan
from prowler.providers.aws.services.apigateway.apigateway_client import (
    apigateway_client,
)


class apigateway_restapi_no_secrets_in_stage_variables(Check):
    """Check that API Gateway REST API stage variables contain no hardcoded secrets."""

    def execute(self) -> list[Check_Report_AWS]:
        findings = []
        secrets_ignore_patterns = apigateway_client.audit_config.get(
            "secrets_ignore_patterns", []
        )
        for rest_api in apigateway_client.rest_apis:
            for stage in rest_api.stages:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=rest_api
                )
                report.resource_arn = stage.arn
                report.resource_id = f"{rest_api.name}/{stage.name}"
                report.status = "PASS"
                report.status_extended = (
                    f"No secrets found in stage variables of API Gateway "
                    f"REST API {rest_api.name} stage {stage.name}."
                )

                if stage.variables:
                    detect_secrets_output = detect_secrets_scan(
                        data=json.dumps(stage.variables, indent=2),
                        excluded_secrets=secrets_ignore_patterns,
                        detect_secrets_plugins=apigateway_client.audit_config.get(
                            "detect_secrets_plugins",
                        ),
                    )

                    if detect_secrets_output:
                        secrets_string = ", ".join(
                            [
                                f"{secret['type']} in variable "
                                f"{list(stage.variables.keys())[secret['line_number'] - 2]}"
                                for secret in detect_secrets_output
                            ]
                        )
                        report.status = "FAIL"
                        report.status_extended = (
                            f"Potential "
                            f"{'secrets' if len(detect_secrets_output) > 1 else 'secret'} "
                            f"found in stage variables of API Gateway REST API "
                            f"{rest_api.name} stage {stage.name} -> {secrets_string}."
                        )

                findings.append(report)

        return findings