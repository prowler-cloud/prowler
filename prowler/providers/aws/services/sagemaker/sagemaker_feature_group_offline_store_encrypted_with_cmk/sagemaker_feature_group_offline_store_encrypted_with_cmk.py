from typing import List

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_feature_group_offline_store_encrypted_with_cmk(Check):
    """Ensure SageMaker Feature Group offline stores are encrypted with a customer-managed KMS key."""

    def execute(self) -> List[Check_Report_AWS]:
        """Return a finding for each SageMaker Feature Group with an offline store.

        Feature Groups without an offline store are out of scope. Feature Groups
        that could not be described are reported as MANUAL.
        """
        findings = []
        for feature_group in sagemaker_client.feature_groups.values():
            if not feature_group.describe_succeeded:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=feature_group
                )
                report.status = "MANUAL"
                report.status_extended = (
                    f"SageMaker Feature Group {feature_group.name} could not be "
                    f"described, so its offline store encryption cannot be evaluated. "
                    f"Verify that sagemaker:DescribeFeatureGroup is granted to the "
                    f"scanning identity."
                )
                findings.append(report)
                continue

            if not feature_group.offline_store_enabled:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=feature_group)
            if feature_group.offline_store_kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker Feature Group {feature_group.name} offline store is "
                    f"encrypted with KMS key {feature_group.offline_store_kms_key_id}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker Feature Group {feature_group.name} offline store is "
                    f"not encrypted with a customer-managed KMS key."
                )
            findings.append(report)

        return findings
