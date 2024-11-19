from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_root_access_key(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # Check if the root credentials are managed by AWS Organizations
        if (
            iam_client.organization_features is not None
            and "RootCredentialsManagement" not in iam_client.organization_features
        ):
            for user in iam_client.credential_report:
                if user["user"] == "<root_account>":
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = user["user"]
                    report.resource_arn = user["arn"]
                    if (
                        user["access_key_1_active"] == "false"
                        and user["access_key_2_active"] == "false"
                    ):
                        report.status = "PASS"
                        report.status_extended = (
                            "Root account does not have access keys."
                        )
                    elif (
                        user["access_key_1_active"] == "true"
                        and user["access_key_2_active"] == "true"
                    ):
                        report.status = "FAIL"
                        report.status_extended = (
                            "Root account has two active access keys."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            "Root account has one active access key."
                        )
                    findings.append(report)
                    break

        return findings
