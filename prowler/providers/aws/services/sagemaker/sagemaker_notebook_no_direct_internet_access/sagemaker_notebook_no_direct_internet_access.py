from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_notebook_no_direct_internet_access(Check):
    def execute(self):
        findings = []

        # Iterate over all notebook instances
        for ni in sagemaker_client.sagemaker_notebook_instances:
            report = Check_Report_AWS(self.metadata())
            report.region = ni.region
            report.resource_id = ni.name
            report.resource_arn = ni.arn
            report.resource_tags = ni.tags

            # Check if direct internet access is disabled
            if ni.direct_internet_access == "Disabled":
                report.status = "PASS"
                report.status_extended = f"SageMaker notebook instance {ni.name} does not have direct internet access enabled."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker notebook instance {ni.name} has direct internet access enabled."

            findings.append(report)

        return findings
