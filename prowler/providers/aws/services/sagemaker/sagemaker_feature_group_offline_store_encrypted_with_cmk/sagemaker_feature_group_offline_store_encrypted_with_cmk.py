from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.sagemaker.sagemaker_client import sagemaker_client


class sagemaker_feature_group_offline_store_encrypted_with_cmk(Check):
    def execute(self):
        findings = []
        for feature_group in sagemaker_client.sagemaker_feature_groups:
            # Only feature groups with an offline store are in scope; the online store is
            # always encrypted and covered elsewhere.
            if not feature_group.offline_store_enabled:
                continue

            report = Check_Report_AWS(metadata=self.metadata(), resource=feature_group)

            if feature_group.offline_store_kms_key_id:
                report.status = "PASS"
                report.status_extended = (
                    f"SageMaker Feature Group {feature_group.name} has its offline store "
                    "encrypted with a KMS Customer Managed Key."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"SageMaker Feature Group {feature_group.name} has an offline store that "
                    "is not encrypted with a KMS Customer Managed Key."
                )

            findings.append(report)

        return findings
