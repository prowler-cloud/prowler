from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_notebook_instance_kms_key_configured(Check):
    def execute(self):
        findings = []

        # Iterate over all notebook instances
        for ni in sagemaker_client.sagemaker_notebook_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = ni.region
            report.resource_id = ni.name
            report.resource_arn = ni.arn
            report.resource_tags = ni.tags

            # Check if KMS key is configured
            if ni.kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker notebook instance {ni.name} has a KMS key configured."
                )
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker notebook instance {ni.name} does not have a KMS key configured."

            findings.append(report)

        return findings
