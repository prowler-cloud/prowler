from typing import List

from prowler.lib.check.models import Check, CheckReportScaleway
from prowler.providers.scaleway.services.iam.iam_client import iam_client


class iam_no_root_api_keys(Check):
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
            placeholder = _IAMDataUnavailableResource(
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

        for api_key in iam_client.api_keys:
            report = CheckReportScaleway(metadata=self.metadata(), resource=api_key)

            if root_user_id and api_key.user_id == root_user_id:
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


class _IAMDataUnavailableResource:
    """Minimal stand-in resource used when the IAM service failed to load.

    ``CheckReportScaleway`` derives ``resource_name``/``resource_id``/
    ``region``/``organization_id`` from the resource via ``getattr`` with
    defaults, so this lightweight object is enough to materialize a
    MANUAL finding without polluting the real domain models.
    """

    def __init__(self, organization_id: str):
        self.name = "iam-data-unavailable"
        self.id = "iam-data-unavailable"
        self.organization_id = organization_id
        self.region = "global"
