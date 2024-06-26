from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # This check is only avaible in Commercial Partition
        if iam_client.audited_partition == "aws":
            if iam_client.account_summary:
                virtual_mfa = False
                report = Check_Report_AWS(self.metadata())
                report.region = iam_client.region
                report.resource_id = "<root_account>"
                report.resource_arn = iam_client.mfa_arn_template

                if iam_client.account_summary["SummaryMap"]["AccountMFAEnabled"] > 0:
                    virtual_mfas = iam_client.virtual_mfa_devices
                    for mfa in virtual_mfas:
                        if "root" in mfa["SerialNumber"]:
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
