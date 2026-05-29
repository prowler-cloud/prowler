from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_models_registry_in_use(Check):
    """Ensure that SageMaker Model Registry has at least one approved model package."""

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports indicating whether the SageMaker Model Registry
            in each region contains at least one approved model package.
        """
        findings = []
        for registry in sagemaker_client.sagemaker_model_registries:
            report = Check_Report_AWS(metadata=self.metadata(), resource=registry)
            if not registry.has_groups:
                report.status = "FAIL"
                report.status_extended = f"SageMaker Model Registry in region {registry.region} has no Model Package Groups."
            elif registry.has_approved_packages:
                report.status = "PASS"
                report.status_extended = f"SageMaker Model Registry in region {registry.region} has at least one approved model package."
            else:
                report.status = "FAIL"
                report.status_extended = f"SageMaker Model Registry in region {registry.region} has Model Package Groups but no approved model packages."
            findings.append(report)
        return findings
