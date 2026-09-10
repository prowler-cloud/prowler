from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_notebook_instance_without_direct_internet_access_configured(Check):
    """Ensure that SageMaker notebook instances have direct internet access disabled."""

    def execute(self) -> list[Check_Report_AWS]:
        """Report whether each notebook instance has direct internet access disabled.

        - PASS: DirectInternetAccess was read and is Disabled.
        - FAIL: DirectInternetAccess was read and is Enabled, so the instance reaches the
          internet directly rather than only through the VPC.
        - MANUAL: DescribeNotebookInstance did not report DirectInternetAccess. Absent is not
          Disabled, and the two cannot share a value here or an instance whose setting was
          never read would be reported compliant.

        Returns:
            One report per notebook instance in the inventory.
        """
        findings = []
        for notebook_instance in sagemaker_client.sagemaker_notebook_instances:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=notebook_instance
            )
            report.status = "PASS"
            report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has direct internet access disabled."
            if notebook_instance.direct_internet_access is None:
                # DescribeNotebookInstance did not report DirectInternetAccess, so the
                # setting is unknown. Defaulting to PASS would report an unread instance
                # as compliant.
                report.status = "MANUAL"
                report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} did not report DirectInternetAccess, so it could not be determined; verify manually."
            elif notebook_instance.direct_internet_access:
                report.status = "FAIL"
                report.status_extended = f"Sagemaker notebook instance {notebook_instance.name} has direct internet access enabled."

            findings.append(report)

        return findings
