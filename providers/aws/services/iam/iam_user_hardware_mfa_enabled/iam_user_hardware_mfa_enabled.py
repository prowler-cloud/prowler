from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client


class iam_user_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.users

        if response:
            for user in response:
                report = Check_Report(self.metadata)
                report.resource_id = user["UserName"]
                report.resource_arn = user["Arn"]
                report.region = "us-east-1"
                mfa_devices = iam_client.list_mfa_devices(user["UserName"])
                if mfa_devices:
                    for mfa_device in mfa_devices:
                        mfa_type = (
                            mfa_device["SerialNumber"].split(":")[5].split("/")[0]
                        )
                        if mfa_type == "mfa" or mfa_type == "sms-mfa":
                            report.status = "FAIL"
                            report.status_extended = f"User {user['UserName']} has a virtual MFA instead of a hardware MFA enabled."
                            findings.append(report)
                        else:
                            report.status = "PASS"
                            report.status_extended = (
                                f"User {user['UserName']} has hardware MFA enabled."
                            )
                            findings.append(report)
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user['UserName']} has not any type of MFA enabled."
                    )
                    findings.append(report)
        else:
            report = Check_Report(self.metadata)
            report.status = "PASS"
            report.status_extended = "There is no IAM users."
            report.region = iam_client.region
            findings.append(report)

        return findings
