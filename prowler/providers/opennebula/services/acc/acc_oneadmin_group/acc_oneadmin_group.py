from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.acc.acc_client import acc_client


class acc_oneadmin_group(Check):
    def execute(self):
        findings = []
        logger.info("Checking if users belong to the oneadmin group")
        for user in acc_client.users:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=user,
            )
            report.status = "PASS"
            report.status_extended = (
                f"User {user.name} does not belong to the oneadmin group."
            )
            if user.group == "oneadmin" and (user.name == "oneadmin" or user.name == "serveradmin"):
                report.status_extended = (
                    f"User {user.name} belongs to the oneadmin group and is the oneadmin or serveradmin user."
                )
            elif user.group == "oneadmin":
                report.status = "FAIL"
                report.status_extended = (
                    f"User {user.name} belongs to the oneadmin group."
                )
            findings.append(report)
        return findings
