from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_notebook_instance_encryption_enabled(Check):
    def execute(self):
        findings = []
        for notebook_instance in sagemaker_client.sagemaker_notebook_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = notebook_instance.region
            report.resource_id = notebook_instance.name
            report.resource_arn = notebook_instance.arn
            report.status = "PASS"
            report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has data encryption enabled"
            if not notebook_instance.kms_key_id:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has data encryption disabled"

            findings.append(report)

        return findings
