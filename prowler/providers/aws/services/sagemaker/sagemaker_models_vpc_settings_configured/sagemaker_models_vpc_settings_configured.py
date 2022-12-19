from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_models_vpc_settings_configured(Check):
    def execute(self):
        findings = []
        for model in sagemaker_client.sagemaker_models:
            report = Check_Report_AWS(self.metadata())
            report.region = model.region
            report.resource_id = model.name
            report.resource_arn = model.arn
            report.status = "PASS"
            report.status_extended = (
                f"Sagemaker notebook instance {model.name} has VPC settings enabled"
            )
            if not model.vpc_config_subnets:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker notebook instance {model.name} has VPC settings disabled"

            findings.append(report)

        return findings
