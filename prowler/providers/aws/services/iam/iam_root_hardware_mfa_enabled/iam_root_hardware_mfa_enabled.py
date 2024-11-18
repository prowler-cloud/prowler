from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # This check is only available in Commercial Partition
        if iam_client.audited_partition == "aws":
            # Check if the root credentials are managed by AWS Organizations
            if (
                iam_client.organization_features is not None
                and "RootCredentialsManagement" not in iam_client.organization_features
            ):
                if iam_client.account_summary:
                    virtual_mfa = False
                    report = Check_Report_AWS(self.metadata())
                    report.region = iam_client.region
                    report.resource_id = "<root_account>"
                    report.resource_arn = iam_client.mfa_arn_template

                    if (
                        iam_client.account_summary["SummaryMap"]["AccountMFAEnabled"]
                        > 0
                    ):
                        for mfa in iam_client.virtual_mfa_devices:
                            # If the ARN of the associated IAM user of the Virtual MFA device is "arn:aws:iam::[aws-account-id]:root", your AWS root account is not using a hardware-based MFA device for MFA protection.
                            if "root" in mfa.get("User", {}).get("Arn", ""):
                                virtual_mfa = True
                                report.status = "FAIL"
                                report.status_extended = "Root account has a virtual MFA instead of a hardware MFA device enabled."
                        if not virtual_mfa:
                            report.status = "PASS"
                            report.status_extended = (
                                "Root account has a hardware MFA device enabled."
                            )
                    else:
                        report.status = "FAIL"
                        report.status_extended = "MFA is not enabled for root account."

                    findings.append(report)

        return findings
