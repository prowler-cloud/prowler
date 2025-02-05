from prowler.lib.check.models import Check, Check_Report_Microsoft365
from prowler.providers.microsoft365.services.admincenter.admincenter_client import (
    admincenter_client,
)


class admincenter_settings_password_never_expire(Check):
    def execute(self) -> Check_Report_Microsoft365:
        findings = []
        for domain in admincenter_client.domains.values():
            report = Check_Report_Microsoft365(self.metadata(), resource=domain)
            report.resource_name = domain.id
            report.status = "FAIL"
            report.status_extended = (
                f"Domain {domain.id} does not have a Password never expires policy."
            )

            if domain.password_validity_period == 2147483647:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.id} Password policy is set to never expire."
                )

            findings.append(report)

        return findings
