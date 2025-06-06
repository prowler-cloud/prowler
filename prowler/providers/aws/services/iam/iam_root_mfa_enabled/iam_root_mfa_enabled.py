from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        if iam_client.credential_report:
            for user in iam_client.credential_report:
                if user["user"] == "<root_account>":
                    # Check if root has any credentials at all
                    has_creds, cred_types = self._has_root_credentials(user)

                    # Only report if root actually has credentials
                    if has_creds:
                        report = Check_Report_AWS(
                            metadata=self.metadata(), resource=user
                        )
                        report.region = iam_client.region
                        report.resource_id = user["user"]
                        report.resource_arn = user["arn"]

                        # Check if organization manages root credentials
                        org_managed = (
                            iam_client.organization_features is not None
                            and "RootCredentialsManagement"
                            in iam_client.organization_features
                        )

                        if user["mfa_active"] == "false":
                            report.status = "FAIL"
                            if org_managed:
                                report.status_extended = (
                                    f"Root account has {', '.join(cred_types)} credentials without MFA "
                                    "despite organizational root management being enabled."
                                )
                            else:
                                report.status_extended = (
                                    "MFA is not enabled for root account."
                                )
                        else:
                            report.status = "PASS"
                            if org_managed and has_creds:
                                report.status_extended = (
                                    f"Root account has {', '.join(cred_types)} credentials with MFA enabled. "
                                    "Consider removing individual root credentials since organizational "
                                    "root management is active."
                                )
                            else:
                                report.status_extended = (
                                    "MFA is enabled for root account."
                                )
                        findings.append(report)

        return findings

    def _has_root_credentials(self, user_data):
        """Check if root user has any form of credentials set"""
        credentials_exist = False
        credential_types = []

        # Check for password
        if user_data["password_enabled"] == "true":
            credentials_exist = True
            credential_types.append("password")

        # Check for access keys
        if user_data["access_key_1_active"] == "true":
            credentials_exist = True
            credential_types.append("access_key_1")

        if user_data["access_key_2_active"] == "true":
            credentials_exist = True
            credential_types.append("access_key_2")

        return credentials_exist, credential_types
