from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # This check is only available in Commercial Partition
        if iam_client.audited_partition == "aws":
            if iam_client.credential_report:
                for user in iam_client.credential_report:
                    if user["user"] == "<root_account>":
                        password_enabled = user["password_enabled"] == "true"
                        access_key_1_active = user["access_key_1_active"] == "true"
                        access_key_2_active = user["access_key_2_active"] == "true"

                        # Only report if root actually has credentials
                        if (
                            password_enabled
                            or access_key_1_active
                            or access_key_2_active
                        ) and iam_client.account_summary:
                            virtual_mfa = False
                            report = Check_Report_AWS(
                                metadata=self.metadata(),
                                resource=user,
                            )
                            report.region = iam_client.region
                            report.resource_id = user["user"]
                            report.resource_arn = iam_client.mfa_arn_template

                            # Check if organization manages root credentials
                            org_managed = (
                                iam_client.organization_features is not None
                                and "RootCredentialsManagement"
                                in iam_client.organization_features
                            )

                            if (
                                iam_client.account_summary["SummaryMap"][
                                    "AccountMFAEnabled"
                                ]
                                > 0
                            ):
                                for mfa in iam_client.virtual_mfa_devices:
                                    # If the ARN of the associated IAM user of the Virtual MFA device is "arn:aws:iam::[aws-account-id]:root", your AWS root account is not using a hardware-based MFA device for MFA protection.
                                    if "root" in mfa.get("User", {}).get("Arn", ""):
                                        virtual_mfa = True
                                        report.status = "FAIL"
                                        if org_managed:
                                            report.status_extended = (
                                                "Root account has credentials with virtual MFA "
                                                "instead of hardware MFA despite organizational root management being enabled."
                                            )
                                        else:
                                            report.status_extended = "Root account has a virtual MFA instead of a hardware MFA device enabled."
                                        break

                                if not virtual_mfa:
                                    report.status = "PASS"
                                    if org_managed:
                                        report.status_extended = (
                                            "Root account has credentials with hardware MFA enabled. "
                                            "Consider removing individual root credentials since organizational "
                                            "root management is active."
                                        )
                                    else:
                                        report.status_extended = "Root account has a hardware MFA device enabled."
                            else:
                                report.status = "FAIL"
                                if org_managed:
                                    report.status_extended = (
                                        "Root account has credentials without MFA "
                                        "despite organizational root management being enabled."
                                    )
                                else:
                                    report.status_extended = (
                                        "MFA is not enabled for root account."
                                    )

                            findings.append(report)

        return findings
