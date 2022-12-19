from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.iam.iam_client import iam_client


class iam_user_hardware_mfa_enabled(Check):
    def execute(self) -> Check_Report_AWS:
        findings = []
        response = iam_client.users

        for user in response:
            report = Check_Report_AWS(self.metadata())
            report.resource_id = user.name
            report.resource_arn = user.arn
            report.region = iam_client.region
            if user.mfa_devices:
                report.status = "PASS"
                report.status_extended = f"User {user.name} has hardware MFA enabled."
                for mfa_device in user.mfa_devices:
                    if mfa_device.type == "mfa" or mfa_device.type == "sms-mfa":
                        report.status = "FAIL"
                        report.status_extended = f"User {user.name} has a virtual MFA instead of a hardware MFA enabled."
                        break

                findings.append(report)
            else:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} has not any type of MFA enabled."
                )
                findings.append(report)

        return findings
