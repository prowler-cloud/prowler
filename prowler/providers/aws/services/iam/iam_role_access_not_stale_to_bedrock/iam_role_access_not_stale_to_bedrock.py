from datetime import datetime, timezone
from typing import Optional

from dateutil.parser import parse

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


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

        if iam_client.roles is None:
            return findings

        for role in iam_client.roles:
            last_accessed_services = iam_client.role_last_accessed_services.get(
                (role.name, role.arn), []
            )
            bedrock_service = self._find_bedrock_service(last_accessed_services)
            if bedrock_service is None:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=role)
            report.region = iam_client.region

            self._evaluate_bedrock_staleness(
                report,
                bedrock_service,
                max_unused_bedrock_days,
                role.name,
                "Role",
            )
            findings.append(report)

        return findings

    @staticmethod
    def _find_bedrock_service(
        last_accessed_services: list[dict],
    ) -> Optional[dict]:
        """Return the Bedrock entry from a service last accessed list."""
        for service in last_accessed_services:
            if service.get("ServiceNamespace") == "bedrock":
                return service
        return None

    @staticmethod
    def _evaluate_bedrock_staleness(
        report: Check_Report_AWS,
        bedrock_service: dict,
        max_days: int,
        identity_name: str,
        identity_type: str,
    ) -> None:
        """Populate a check report based on Bedrock access recency."""
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
