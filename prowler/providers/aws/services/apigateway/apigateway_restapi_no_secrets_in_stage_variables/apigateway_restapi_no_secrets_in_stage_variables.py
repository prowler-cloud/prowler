import json

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.lib.utils.utils import (
    SecretsScanError,
    annotate_verified_secrets,
    detect_secrets_scan_batch,
)
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
        validate = apigateway_client.audit_config.get("secrets_validate", False)

        # Collect one payload per stage (its variables) and scan them all in
        # batched Kingfisher invocations instead of one subprocess per stage.
        # Findings are keyed by (rest_api index, stage index).
        def payloads():
            for api_index, rest_api in enumerate(apigateway_client.rest_apis):
                for stage_index, stage in enumerate(rest_api.stages):
                    if stage.variables:
                        yield (api_index, stage_index), json.dumps(
                            stage.variables, indent=2
                        )

        scan_error = None
        try:
            batch_results = detect_secrets_scan_batch(
                payloads(),
                excluded_secrets=secrets_ignore_patterns,
                validate=validate,
            )
        except SecretsScanError as error:
            batch_results = {}
            scan_error = error

        for api_index, rest_api in enumerate(apigateway_client.rest_apis):
            for stage_index, stage in enumerate(rest_api.stages):
                report = Check_Report_AWS(metadata=self.metadata(), resource=rest_api)
                report.resource_arn = stage.arn
                report.resource_id = f"{rest_api.name}/{stage.name}"
                report.status = "PASS"
                report.status_extended = (
                    f"No secrets found in stage variables of API Gateway "
                    f"REST API {rest_api.name} stage {stage.name}."
                )

                if stage.variables:
                    if scan_error:
                        report.status = "MANUAL"
                        report.status_extended = (
                            f"Could not scan stage variables of API Gateway REST API "
                            f"{rest_api.name} stage {stage.name} for secrets: "
                            f"{scan_error}; manual review is required."
                        )
                        findings.append(report)
                        continue

                    detect_secrets_output = batch_results.get((api_index, stage_index))
                    if detect_secrets_output:
                        variable_names = list(stage.variables.keys())
                        secrets_string = ", ".join(
                            [
                                f"{secret['type']} in variable "
                                f"{variable_names[secret['line_number'] - 2]}"
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
                        annotate_verified_secrets(report, detect_secrets_output)

                findings.append(report)

        return findings
