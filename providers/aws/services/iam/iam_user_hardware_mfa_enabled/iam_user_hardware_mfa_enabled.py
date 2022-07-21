from lib.check.models import Check, Check_Report
from providers.aws.services.iam.iam_service import iam_client


class iam_user_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report:
        findings = []
        response = iam_client.users

        if response:
            for user in response:
                report = Check_Report(self.metadata)
                report.resource_id = user.name
                report.resource_arn = user.arn
                report.region = "us-east-1"
                if user.mfa_devices:
                    for mfa_device in user.mfa_devices:
                        if mfa_device.type == "mfa" or mfa_device.type == "sms-mfa":
                            report.status = "FAIL"
                            report.status_extended = f"User {user.name} has a virtual MFA instead of a hardware MFA enabled."
                            findings.append(report)
                        else:
                            report.status = "PASS"
                            report.status_extended = (
                                f"User {user.name} has hardware MFA enabled."
                            )
                            findings.append(report)
                else:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"User {user.name} has not any type of MFA enabled."
                    )
                    findings.append(report)
        else:
            report = Check_Report(self.metadata)
            report.status = "PASS"
            report.status_extended = "There is no IAM users."
            report.region = iam_client.region
            findings.append(report)

        return findings
