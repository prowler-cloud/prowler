from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.glue.glue_client import glue_client


class glue_ml_transform_encrypted_at_rest(Check):
    def execute(self):
        findings = []

        for ml_transform in glue_client.ml_transforms.values():
            report = Check_Report_AWS(self.metadata(), ml_transform)
            report.status = "PASS"
            report.status_extended = (
                f"Glue ML Transform {ml_transform.name} is encrypted at rest."
            )

            if ml_transform.user_data_encryption == "DISABLED":
                report.status = "FAIL"
                report.status_extended = (
                    f"Glue ML Transform {ml_transform.name} is not encrypted at rest."
                )

            findings.append(report)

        return findings
