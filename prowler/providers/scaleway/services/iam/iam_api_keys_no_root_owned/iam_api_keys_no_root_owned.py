from typing import List

from prowler.lib.check.models import Check, CheckReportScaleway
from prowler.providers.scaleway.services.iam.iam_client import iam_client
from prowler.providers.scaleway.services.iam.iam_service import (
    ScalewayIAMDataUnavailable,
)


class iam_api_keys_no_root_owned(Check):
    """Ensure no Scaleway IAM API key is owned by the account root user.

    The account root user is the original Scaleway account owner. API keys
    bound to that bearer bypass IAM policies and grant unrestricted access
    to the entire organization; rotating or losing them is a critical
    incident. Day-to-day automation should rely on IAM users or
    applications scoped through policies instead.
    """

    def execute(self) -> List[CheckReportScaleway]:
        """Iterate over the API keys cached by the IAM service.

        The check degrades to ``MANUAL`` when the IAM service could not
        load the prerequisite data (users or API keys) — emitting ``PASS``
        in those cases would silently mask the very condition the check
        exists to detect.

        Returns:
            One ``CheckReportScaleway`` per discovered API key. ``FAIL``
            when the bearer is the account root user, ``PASS`` otherwise.
            A single ``MANUAL`` report is emitted when underlying IAM data
            is unavailable.
        """
        findings: List[CheckReportScaleway] = []

        # If we could not even load the users we cannot tell who the root
        # bearer is, so every API key would falsely PASS. Surface MANUAL
        # explicitly so the operator investigates.
        if not iam_client.users_loaded or not iam_client.api_keys_loaded:
            placeholder = ScalewayIAMDataUnavailable(
                organization_id=iam_client.organization_id
            )
            report = CheckReportScaleway(metadata=self.metadata(), resource=placeholder)
            report.status = "MANUAL"
            report.status_extended = (
                "Could not retrieve Scaleway IAM users or API keys for "
                f"organization {iam_client.organization_id}. Verify the "
                "API key has the IAMReadOnly policy and rerun."
            )
            findings.append(report)
            return findings

        root_user_id = iam_client.account_root_user_id

        # The account root user could not be resolved (typically an
        # application-scoped API key with no IAM users visible). Without it
        # every key would fall through to PASS, masking root-owned keys, so
        # surface MANUAL instead of a silent clean result.
        if not root_user_id:
            placeholder = ScalewayIAMDataUnavailable(
                organization_id=iam_client.organization_id
            )
            report = CheckReportScaleway(metadata=self.metadata(), resource=placeholder)
            report.status = "MANUAL"
            report.status_extended = (
                "Could not determine the Scaleway account root user for "
                f"organization {iam_client.organization_id}. This typically "
                "happens with application-scoped API keys when no IAM users "
                "are visible. Verify the API key has the IAMReadOnly policy "
                "and rerun."
            )
            findings.append(report)
            return findings

        for api_key in iam_client.api_keys:
            report = CheckReportScaleway(metadata=self.metadata(), resource=api_key)

            if api_key.user_id == root_user_id:
                report.status = "FAIL"
                report.status_extended = (
                    f"Scaleway API key {api_key.access_key} is owned by the "
                    f"account root user ({root_user_id}). Replace it with an "
                    f"API key bound to a dedicated IAM user or application."
                )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Scaleway API key {api_key.access_key} is not owned by "
                    f"the account root user."
                )

            findings.append(report)

        return findings
