from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_notebook_instance_root_access_disabled(Check):
    def execute(self):
        findings = []
        for notebook_instance in sagemaker_client.sagemaker_notebook_instances:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource_metadata=notebook_instance
            )
            report.status = "PASS"
            report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has root access disabled."
            if notebook_instance.root_access:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has root access enabled."

            findings.append(report)

        return findings
