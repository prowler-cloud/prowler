from datetime import datetime, timezone

from dateutil.parser import parse

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class bedrock_access_not_stale(Check):
    """Detect stale identities with unused Bedrock permissions.

    This check evaluates whether IAM users and roles with Bedrock service
    permissions have actively used those permissions within the configured
    threshold (default 60 days).

    - PASS: The identity has accessed Bedrock within the allowed period.
    - FAIL: The identity has Bedrock permissions but has not used them
      within the allowed period or has never used them.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the Bedrock access staleness check.

        Iterates over IAM users and roles, inspecting service last accessed
        data for the ``bedrock`` namespace. Identities whose last Bedrock
        access exceeds the configured threshold are reported as non-compliant.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        max_unused_bedrock_days = iam_client.audit_config.get(
            "max_unused_bedrock_access_days", 60
        )

        # Lazy-load role last accessed data (only when this check runs)
        if not iam_client.role_last_accessed_services:
            iam_client._get_role_last_accessed_services()

        # Check IAM users
        for (
            user_data,
            last_accessed_services,
        ) in iam_client.last_accessed_services.items():
            user_name = user_data[0]
            user_arn = user_data[1]

            bedrock_service = self._find_bedrock_service(last_accessed_services)
            if bedrock_service is None:
                continue

            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={"name": user_name, "arn": user_arn},
            )
            report.resource_id = user_name
            report.resource_arn = user_arn
            report.region = iam_client.region
            # Retrieve tags from the user object
            for iam_user in iam_client.users:
                if iam_user.arn == user_arn:
                    report.resource_tags = iam_user.tags
                    break

            self._evaluate_staleness(
                report, bedrock_service, max_unused_bedrock_days, user_name, "User"
            )
            findings.append(report)

        # Check IAM roles
        for (
            role_data,
            last_accessed_services,
        ) in iam_client.role_last_accessed_services.items():
            role_name = role_data[0]
            role_arn = role_data[1]

            bedrock_service = self._find_bedrock_service(last_accessed_services)
            if bedrock_service is None:
                continue

            report = Check_Report_AWS(
                metadata=self.metadata(),
                resource={"name": role_name, "arn": role_arn},
            )
            report.resource_id = role_name
            report.resource_arn = role_arn
            report.region = iam_client.region
            # Retrieve tags from the role object
            if iam_client.roles is not None:
                for iam_role in iam_client.roles:
                    if iam_role.arn == role_arn:
                        report.resource_tags = iam_role.tags
                        break

            self._evaluate_staleness(
                report, bedrock_service, max_unused_bedrock_days, role_name, "Role"
            )
            findings.append(report)

        return findings

    @staticmethod
    def _find_bedrock_service(
        last_accessed_services: list[dict],
    ) -> dict | None:
        """Return the Bedrock entry from a service last accessed list.

        Args:
            last_accessed_services: List of service last accessed records.

        Returns:
            The dictionary for the ``bedrock`` namespace, or ``None``.
        """
        for service in last_accessed_services:
            if service.get("ServiceNamespace") == "bedrock":
                return service
        return None

    @staticmethod
    def _evaluate_staleness(
        report: Check_Report_AWS,
        bedrock_service: dict,
        max_days: int,
        identity_name: str,
        identity_type: str,
    ) -> None:
        """Populate the report based on Bedrock access recency.

        Args:
            report: The check report to populate.
            bedrock_service: The Bedrock service last accessed record.
            max_days: Maximum allowed days since last Bedrock access.
            identity_name: Name of the IAM identity.
            identity_type: Either ``User`` or ``Role``.
        """
        last_authenticated = bedrock_service.get("LastAuthenticated")
        if last_authenticated is None:
            report.status = "FAIL"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} has Bedrock permissions "
                f"but has never used them."
            )
            return

        if isinstance(last_authenticated, str):
            last_authenticated = parse(last_authenticated)

        days_since_access = (datetime.now(timezone.utc) - last_authenticated).days

        if days_since_access > max_days:
            report.status = "FAIL"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} has not accessed Bedrock "
                f"in {days_since_access} days (threshold: {max_days} days)."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} accessed Bedrock "
                f"{days_since_access} days ago (threshold: {max_days} days)."
            )
