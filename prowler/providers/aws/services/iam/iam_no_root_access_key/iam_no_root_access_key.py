from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_no_root_access_key(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []

        if iam_client.credential_report:
            for user in iam_client.credential_report:
                if user["user"] == "<root_account>":
                    password_enabled = user["password_enabled"] == "true"
                    access_key_1_active = user["access_key_1_active"] == "true"
                    access_key_2_active = user["access_key_2_active"] == "true"

                    # Only report if root actually has credentials
                    if password_enabled or access_key_1_active or access_key_2_active:
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

                        if not access_key_1_active and not access_key_2_active:
                            report.status = "PASS"
                            if org_managed:
                                report.status_extended = (
                                    "Root account has password configured but no access keys. "
                                    "Consider removing individual root credentials since organizational "
                                    "root management is active."
                                )
                            else:
                                report.status_extended = (
                                    "Root account does not have access keys."
                                )
                        elif access_key_1_active and access_key_2_active:
                            report.status = "FAIL"
                            if org_managed:
                                report.status_extended = (
                                    "Root account has two active access keys "
                                    "despite organizational root management being enabled."
                                )
                            else:
                                report.status_extended = (
                                    "Root account has two active access keys."
                                )
                        else:
                            report.status = "FAIL"
                            if org_managed:
                                report.status_extended = (
                                    "Root account has one active access key "
                                    "despite organizational root management being enabled."
                                )
                            else:
                                report.status_extended = (
                                    "Root account has one active access key."
                                )
                        findings.append(report)
                    break

        return findings
