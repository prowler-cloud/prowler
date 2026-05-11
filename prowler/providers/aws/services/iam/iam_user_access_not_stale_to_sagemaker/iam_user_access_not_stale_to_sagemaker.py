from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    evaluate_sagemaker_staleness,
    find_sagemaker_service,
)


class iam_user_access_not_stale_to_sagemaker(Check):
    """Detect IAM users with stale SageMaker permissions.

    This check evaluates whether IAM users with SageMaker service permissions
    have actively used those permissions within the configured threshold
    (default 90 days).

    - PASS: The user has accessed SageMaker within the allowed period.
    - FAIL: The user has SageMaker permissions but has not used them within
      the allowed period or has never used them.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the SageMaker access staleness check for IAM users.

        Iterates over IAM users, inspecting service last accessed data for
        the ``sagemaker`` namespace. Users whose last SageMaker access exceeds
        the configured threshold are reported as non-compliant.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        max_unused_sagemaker_days = iam_client.audit_config.get(
            "max_unused_sagemaker_access_days", 90
        )

        for user in iam_client.users:
            last_accessed_services = iam_client.last_accessed_services.get(
                (user.name, user.arn), []
            )
            sagemaker_service = find_sagemaker_service(last_accessed_services)
            if sagemaker_service is None:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=user)
            report.region = iam_client.region

            evaluate_sagemaker_staleness(
                report,
                sagemaker_service,
                max_unused_sagemaker_days,
                user.name,
                "User",
            )
            findings.append(report)

        return findings
