from datetime import datetime, timezone
from typing import List

from prowler.lib.check.models import Check, CheckReportVercel, Severity
from prowler.providers.vercel.services.domain.domain_client import domain_client


class domain_ssl_certificate_valid(Check):
    """Check if domains have a valid, non-expired SSL certificate.

    This class verifies whether each Vercel domain has an SSL certificate
    that is provisioned, not expired, and not about to expire. The
    expiration threshold is configurable via ``days_to_expire_threshold``
    in audit_config (default: 7 days).
    """

    def execute(self) -> List[CheckReportVercel]:
        """Execute the Vercel Domain SSL Certificate check.

        Iterates over all domains and checks SSL certificate presence and
        expiration status.

        Returns:
            List[CheckReportVercel]: A list of reports for each domain.
        """
        findings = []
        now = datetime.now(timezone.utc)
        days_to_expire_threshold = domain_client.audit_config.get(
            "days_to_expire_threshold", 7
        )

        for domain in domain_client.domains.values():
            report = CheckReportVercel(
                metadata=self.metadata(),
                resource=domain,
                resource_name=domain.name,
                resource_id=domain.id or domain.name,
            )

            if domain.ssl_certificate is None:
                report.status = "FAIL"
                report.check_metadata.Severity = Severity.high
                report.status_extended = f"Domain {domain.name} does not have an SSL certificate provisioned."
            elif (
                domain.ssl_certificate.expires_at is not None
                and domain.ssl_certificate.expires_at <= now
            ):
                report.status = "FAIL"
                report.check_metadata.Severity = Severity.critical
                report.status_extended = (
                    f"Domain {domain.name} has an SSL certificate that expired "
                    f"on {domain.ssl_certificate.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                )
            elif domain.ssl_certificate.expires_at is not None:
                days_left = (domain.ssl_certificate.expires_at - now).days
                if days_left <= days_to_expire_threshold:
                    report.status = "FAIL"
                    report.check_metadata.Severity = Severity.high
                    report.status_extended = (
                        f"Domain {domain.name} has an SSL certificate expiring "
                        f"in {days_left} days "
                        f"on {domain.ssl_certificate.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                    )
                else:
                    report.status = "PASS"
                    report.status_extended = (
                        f"Domain {domain.name} has a valid SSL certificate expiring "
                        f"on {domain.ssl_certificate.expires_at.strftime('%Y-%m-%d %H:%M UTC')}."
                    )
            else:
                report.status = "PASS"
                report.status_extended = (
                    f"Domain {domain.name} has an SSL certificate provisioned."
                )

            findings.append(report)

        return findings
