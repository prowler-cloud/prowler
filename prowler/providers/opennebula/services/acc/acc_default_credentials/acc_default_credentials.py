from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.acc.acc_client import acc_client


class acc_default_credentials(Check):
    def execute(self):
        findings = []
        logger.info("Checking for weak passwords in OpenNebula users...")
        for user in acc_client.users:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=user,
            )
            report.status = "PASS"
            report.status_extended = (
                f"User {user.name} has a strong password."
            )
            if user.weak_password:
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} has a weak password."
                )
            findings.append(report)
        return findings
