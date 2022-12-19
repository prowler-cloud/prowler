from datetime import datetime

from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.directoryservice.directoryservice_client import (
    directoryservice_client,
)

DAYS_TO_EXPIRE_THRESHOLD = 90
"""Number of days to notify about a certificate expiration"""


class directoryservice_ldap_certificate_expiration(Check):
    def execute(self):
        findings = []
        for directory in directoryservice_client.directories.values():
            for certificate in directory.certificates:
                report = Check_Report_AWS(self.metadata())
                report.region = directory.region
                report.resource_id = certificate.id

                remaining_days_to_expire = (
                    certificate.expiry_date_time - datetime.today()
                ).days
                if remaining_days_to_expire <= DAYS_TO_EXPIRE_THRESHOLD:
                    report.status = "FAIL"
                    report.status_extended = f"LDAP Certificate {certificate.id} configured at {directory.id} is about to expire in {remaining_days_to_expire} days"
                else:
                    report.status = "PASS"
                    report.status_extended = f"LDAP Certificate {certificate.id} configured at {directory.id} expires in {remaining_days_to_expire} days"

                findings.append(report)

        return findings
