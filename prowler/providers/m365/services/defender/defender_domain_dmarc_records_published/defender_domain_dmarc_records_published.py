import re

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_domain_dmarc_records_published(Check):
    """
    Check if DMARC records are published with an enforcing policy for all Exchange Online domains.

    DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds on
    SPF and DKIM to stop spoofing/phishing from your domains. This check verifies that
    a DMARC TXT record exists at _dmarc.<domain> with an enforcing policy (p=quarantine
    or p=reject) for every accepted Exchange Online domain.
    """

    def execute(self):
        """
        Execute the check to verify if DMARC records are published for all domains.

        This method looks up the DMARC TXT record at _dmarc.<domain> for each Exchange
        Online domain and validates that it contains an enforcing policy.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for config in defender_client.dkim_configurations:
            domain = config.id
            report = CheckReportM365(
                metadata=self.metadata(),
                resource=config,
                resource_name=domain,
                resource_id=domain,
            )

            dmarc_record = self._lookup_dmarc_record(domain)

            if not dmarc_record:
                report.status = "FAIL"
                report.status_extended = (
                    f"No DMARC record found for domain {domain}."
                )
            else:
                # Validate the DMARC record has the correct version tag
                if not dmarc_record.upper().startswith("V=DMARC1"):
                    report.status = "FAIL"
                    report.status_extended = (
                        f"DMARC record found for domain {domain} but is malformed: "
                        f"missing or invalid V=DMARC1 version tag."
                    )
                else:
                    policy = self._get_policy_value(dmarc_record)

                    if policy in ("reject", "quarantine"):
                        report.status = "PASS"
                        report.status_extended = (
                            f"DMARC record with enforcing policy p={policy} "
                            f"exists for domain {domain}."
                        )
                    elif policy == "none":
                        report.status = "FAIL"
                        report.status_extended = (
                            f"DMARC record exists for domain {domain} but uses "
                            f"monitoring-only policy p=none."
                        )
                    else:
                        report.status = "FAIL"
                        report.status_extended = (
                            f"DMARC record found for domain {domain} but has an "
                            f"missing or unrecognized policy."
                        )

            findings.append(report)

        return findings

    def _lookup_dmarc_record(self, domain):
        """
        Look up the DMARC TXT record for a given domain.

        DMARC records are published as TXT records at _dmarc.<domain>.

        Args:
            domain: The domain to look up the DMARC record for.

        Returns:
            str or None: The DMARC record content if found, None otherwise.
        """
        import dns.resolver

        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for rdata in answers:
                record = b"".join(rdata.strings).decode("utf-8")
                if "V=DMARC1" in record.upper():
                    return record
        except (
            dns.resolver.NoAnswer,
            dns.resolver.NXDOMAIN,
            dns.resolver.NoNameservers,
            dns.resolver.Timeout,
            dns.resolver.Timeout,
        ):
            pass
        except Exception:
            pass

        return None

    def _get_policy_value(self, content):
        """
        Extract the DMARC policy value (reject, quarantine, or none) from a DMARC record.

        Args:
            content: The DMARC record string.

        Returns:
            str: The policy value ("reject", "quarantine", "none") or empty string if not found.
        """
        match = re.search(r"p\s*=\s*(\w+)", content, re.IGNORECASE)
        if match:
            return match.group(1).lower()
        return ""
