from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_endpoint_configuration_kms_key_configured(Check):
    def execute(self):
        findings = []

        # Iterate over all endpoint configurations in the dictionary
        for ec in sagemaker_client.endpoint_configs.values():
            report = Check_Report_AWS(self.metadata())
            report.region = ec.region
            report.resource_id = ec.name
            report.resource_arn = ec.arn
            report.resource_tags = ec.tags

            # Check if KMS key is configured
            if ec.kms_key_id:
                report.status = "PASS"
                report.status_extended = f"SageMaker endpoint configuration {ec.name} has a KMS key configured."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker endpoint configuration {ec.name} does not have a KMS key configured."

            findings.append(report)

        return findings
