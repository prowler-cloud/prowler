from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client
from prowler.providers.aws.services.iam.lib.policy import (
    evaluate_bedrock_staleness,
    find_bedrock_service,
)


class iam_role_access_not_stale_to_bedrock(Check):
    """Detect IAM roles with stale Bedrock permissions.

    This check evaluates whether IAM roles with Bedrock service permissions
    have actively used those permissions within the configured threshold
    (default 60 days).

    - PASS: The role has accessed Bedrock within the allowed period.
    - FAIL: The role has Bedrock permissions but has not used them within
      the allowed period or has never used them.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock access staleness check for IAM roles.

        Iterates over IAM roles, inspecting service last accessed data for
        the ``bedrock`` namespace. Roles whose last Bedrock access exceeds
        the configured threshold are reported as non-compliant.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        max_unused_bedrock_days = iam_client.audit_config.get(
            "max_unused_bedrock_access_days", 60
        )

        for (
            role_data,
            last_accessed_services,
        ) in iam_client.role_last_accessed_services.items():
            role_name = role_data[0]
            role_arn = role_data[1]

            bedrock_service = find_bedrock_service(last_accessed_services)
            if bedrock_service is None:
                continue

            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={"name": role_name, "arn": role_arn},
            )
            report.resource_id = role_name
            report.resource_arn = role_arn
            report.region = iam_client.region
            if iam_client.roles is not None:
                for iam_role in iam_client.roles:
                    if iam_role.arn == role_arn:
                        report.resource_tags = iam_role.tags
                        break

            evaluate_bedrock_staleness(
                report, bedrock_service, max_unused_bedrock_days, role_name, "Role"
            )
            findings.append(report)

        return findings
