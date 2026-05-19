from datetime import datetime, timezone
from typing import Optional

from dateutil.parser import parse

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


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
            sagemaker_service = self._find_sagemaker_service(last_accessed_services)
            if sagemaker_service is None:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=user)
            report.region = iam_client.region

            self._evaluate_sagemaker_staleness(
                report,
                sagemaker_service,
                max_unused_sagemaker_days,
                user.name,
                "User",
            )
            findings.append(report)

        return findings

    @staticmethod
    def _find_sagemaker_service(
        last_accessed_services: list[dict],
    ) -> Optional[dict]:
        """Return the SageMaker entry from a service last accessed list."""
        for service in last_accessed_services:
            if service.get("ServiceNamespace") == "sagemaker":
                return service
        return None

    @staticmethod
    def _evaluate_sagemaker_staleness(
        report: Check_Report_AWS,
        sagemaker_service: dict,
        max_days: int,
        identity_name: str,
        identity_type: str,
    ) -> None:
        """Populate a check report based on SageMaker access recency."""
        last_authenticated = sagemaker_service.get("LastAuthenticated")
        if last_authenticated is None:
            report.status = "FAIL"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} has SageMaker permissions "
                f"but has never used them."
            )
            return

        if isinstance(last_authenticated, str):
            last_authenticated = parse(last_authenticated)

        days_since_access = (datetime.now(timezone.utc) - last_authenticated).days

        if days_since_access > max_days:
            report.status = "FAIL"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} has not accessed SageMaker "
                f"in {days_since_access} days (threshold: {max_days} days)."
            )
        else:
            report.status = "PASS"
            report.status_extended = (
                f"IAM {identity_type} {identity_name} accessed SageMaker "
                f"{days_since_access} days ago (threshold: {max_days} days)."
            )
