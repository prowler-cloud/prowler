from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client


class bedrock_model_invocation_logging_text_data_enabled(Check):
    """Ensure model invocation logging delivers prompt and response text.

    Model invocation logging can name a CloudWatch log group or S3 bucket while excluding the
    request and response bodies, so a configured destination does not establish that prompts and
    completions are captured. This check is scoped to Regions where invocation logging is already
    enabled: a Region with logging switched off is the subject of
    bedrock_model_invocation_logging_enabled and is not reported here.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for region, logging in bedrock_client.logging_configurations.items():
            # Skip-if-absent: only Regions that already deliver logs are in scope.
            if not logging.enabled:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=logging)
            report.region = region
            # "model-invocation-logging", as both siblings on this configuration use. The account
            # id identified no resource -- every Region reported the same id, and the ARN beside it
            # already carries the account -- so a reader could not tell two Regions' findings apart
            # by resource_id alone.
            report.resource_id = "model-invocation-logging"
            report.resource_arn = (
                bedrock_client._get_model_invocation_logging_arn_template(region)
            )

            if logging.text_data_delivery_enabled is None:
                # The API did not report the flag. Absent is not False, and reporting it as
                # compliant would assert content capture that was never confirmed.
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock Model Invocation Logging is enabled in region {region} but the "
                    "text data delivery setting was not returned; verify manually that prompt "
                    "and response text is delivered."
                )
            elif logging.text_data_delivery_enabled:
                report.status = "PASS"
                report.status_extended = (
                    f"Bedrock Model Invocation Logging in region {region} delivers prompt and "
                    "response text."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"Bedrock Model Invocation Logging in region {region} excludes prompt and "
                    "response text, so invocation content is not captured."
                )

            findings.append(report)

        return findings
