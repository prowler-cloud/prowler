from prowler.lib.logger import logger
from prowler.lib.check.models import Check, Check_Report_OpenNebula
from prowler.providers.opennebula.services.acc.acc_client import acc_client

class acc_token_rotation(Check):
    def execute(self):
        findings = []
        logger.info("Checking for non-expiring API tokens in users...")
        for user in acc_client.users:
            report = Check_Report_OpenNebula(
                metadata=self.metadata(),
                resource=user,
            )
            report.status = "PASS"
            report.status_extended = f"User {user.name} has no API tokens."
            if hasattr(user, "tokens"):
                for token in user.tokens:
                    if token.get("expiration") == -1:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"User {user.name} has a non-expiring API token: {token.get('value')[:5]}..."
                        )
                    else:
                        report.status = "PASS"
                        report.status_extended = (
                            f"User {user.name} has a token with expiration: {token.get('expiration')}"
                        )
            findings.append(report)
        return findings
