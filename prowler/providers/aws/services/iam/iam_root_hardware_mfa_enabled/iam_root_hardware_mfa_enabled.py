from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_root_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        # This check is only avaible in Commercial Partition
        if iam_client.partition == "aws":
            virtual_mfa = False
            report = Check_Report_AWS(self.metadata())
            report.region = iam_client.region
            report.resource_id = "root"
            report.resource_arn = f"arn:aws:iam::{iam_client.account}:root"

            if iam_client.account_summary["SummaryMap"]["AccountMFAEnabled"] > 0:
                virtual_mfas = iam_client.virtual_mfa_devices
                for mfa in virtual_mfas:
                    if "root" in mfa["SerialNumber"]:
                        virtual_mfa = True
                        report.status = "FAIL"
                        report.status_extended = "Root account has a virtual MFA instead of a hardware MFA enabled."
                if not virtual_mfa:
                    report.status = "PASS"
                    report.status_extended = "Root account has hardware MFA enabled."
            else:
                report.status = "FAIL"
                report.status_extended = "MFA is not enabled for root account."

            findings.append(report)

        return findings
