from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    evaluate_bedrock_staleness,
    find_bedrock_service,
)


class iam_user_access_not_stale_to_bedrock(Check):
    """Detect IAM users with stale Bedrock permissions.

    This check evaluates whether IAM users with Bedrock service permissions
    have actively used those permissions within the configured threshold
    (default 60 days).

    - PASS: The user has accessed Bedrock within the allowed period.
    - FAIL: The user has Bedrock permissions but has not used them within
      the allowed period or has never used them.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock access staleness check for IAM users.

        Iterates over IAM users, inspecting service last accessed data for
        the ``bedrock`` namespace. Users whose last Bedrock access exceeds
        the configured threshold are reported as non-compliant.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        max_unused_bedrock_days = iam_client.audit_config.get(
            "max_unused_bedrock_access_days", 60
        )

        for (
            user_data,
            last_accessed_services,
        ) in iam_client.last_accessed_services.items():
            user_name = user_data[0]
            user_arn = user_data[1]

            bedrock_service = find_bedrock_service(last_accessed_services)
            if bedrock_service is None:
                continue

            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={"name": user_name, "arn": user_arn},
            )
            report.resource_id = user_name
            report.resource_arn = user_arn
            report.region = iam_client.region
            for iam_user in iam_client.users:
                if iam_user.arn == user_arn:
                    report.resource_tags = iam_user.tags
                    break

            evaluate_bedrock_staleness(
                report, bedrock_service, max_unused_bedrock_days, user_name, "User"
            )
            findings.append(report)

        return findings
