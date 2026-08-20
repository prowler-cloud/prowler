import re

from prowler.lib.check.models import Check, CheckReportM365
from prowler.lib.logger import logger
from prowler.providers.m365.services.defender.defender_client import defender_client

# DNS exceptions indicating that no answer could be obtained: a genuine
# absence (NXDOMAIN, NoAnswer) versus a transient resolver failure (Timeout,
# NoNameservers). Absent signals "no record found"; failure signals that the
# lookup must be retried manually.
import dns.resolver as _dns_resolver

_DNS_ABSENT_EXCEPTIONS = (
    _dns_resolver.NoAnswer,
    _dns_resolver.NXDOMAIN,
)
_DNS_FAILURE_EXCEPTIONS = (
    _dns_resolver.NoNameservers,
    _dns_resolver.Timeout,
)


class defender_domain_dmarc_records_published(Check):
    """
    Check if DMARC records are published with an enforcing policy for all Exchange Online domains.

    DMARC (Domain-based Message Authentication, Reporting, and Conformance) builds on
    SPF and DKIM to stop spoofing/phishing from your domains. This check verifies that
    a DMARC TXT record exists at _dmarc.<domain> with an enforcing policy (p=quarantine
    or p=reject) for every accepted Exchange Online domain.
    """

    def execute(self) -> list[CheckReportM365]:
        """
        Execute the check to verify if DMARC records are published for all domains.

        This method looks up the DMARC TXT record at _dmarc.<domain> for each Exchange
        Online domain and validates that it contains an enforcing policy.

        Returns:
            list[CheckReportM365]: A list of reports containing the result of the check.
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

            records, dns_error = self._lookup_dmarc_record(domain)

            if records is None:
                # No TXT records at _dmarc.<domain> at all.
                report.status = "FAIL"
                report.status_extended = (
                    f"No DMARC record found for domain {domain}."
                )
            elif not records:
                # DNS resolver failure -> treat as FAIL.
                report.status = "FAIL"
                if dns_error:
                    report.status_extended = (
                        f"Could not resolve DMARC record for domain {domain} due to a "
                        f"{dns_error}; manual review is required."
                    )
                else:
                    report.status_extended = (
                        f"Could not resolve DMARC record for domain {domain} due to a "
                        f"DNS resolver error; manual review is required."
                    )
            else:
                # Validate by parsing semicolon-delimited tags.
                # Each record must have v=DMARC1 as the first tag.
                dmarc_records = [
                    r for r in records if self._is_valid_dmarc_record(r)
                ]
                if len(dmarc_records) == 0:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"TXT record found at _dmarc.{domain} but it is not a valid "
                        f"DMARC record: malformed or missing V=DMARC1 version tag."
                    )
                elif len(dmarc_records) > 1:
                    report.status = "FAIL"
                    report.status_extended = (
                        f"Multiple DMARC records found for domain {domain}: "
                        f"exactly one V=DMARC1 record is expected."
                    )
                else:
                    dmarc_record = dmarc_records[0]
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
                            f"DMARC record found for domain {domain} but has a "
                            f"malformed or unrecognized policy."
                        )

            findings.append(report)

        return findings

    def _lookup_dmarc_record(self, domain):
        """
        Look up the TXT records at _dmarc.<domain>.

        DMARC records are published as TXT records at _dmarc.<domain>.

        Args:
            domain: The domain to look up the DMARC record for.

        Returns:
            tuple: (records, error_message) where:
            - records is a list of TXT record strings, or None if no records exist
              (NXDOMAIN, NoAnswer), or an empty list if the DNS resolver failed.
            - error_message is a string describing the DNS error, or None.
        """
        import dns.resolver

        try:
            answers = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            records = []
            for rdata in answers:
                try:
                    records.append(b"".join(rdata.strings).decode("utf-8"))
                except (UnicodeDecodeError, ValueError):
                    # Decode failure: treat as transient resolver failure.
                    return [], "DNS record decode failure"
            return records or None, None
        except _DNS_FAILURE_EXCEPTIONS as e:
            # Transient resolver failure. An empty list is the sentinel for the
            # caller to report FAIL.
            error_type = type(e).__name__
            return [], f"DNS resolver error ({error_type})"
        except _DNS_ABSENT_EXCEPTIONS:
            # No TXT records at all (domain absent or no answer).
            return None, None
        except Exception as e:
            # Unknown DNS error: treat as resolver failure for safety.
            logger.error(
                f"{type(e).__name__}[{e.__traceback__.tb_lineno}]: {e}"
            )
            return [], f"DNS resolver error ({type(e).__name__})"

    def _is_valid_dmarc_record(self, content: str) -> bool:
        """
        Check whether a TXT record is a valid DMARC record.

        Parses the record as semicolon-delimited tags and requires:
        - The first tag must be exactly ``v=DMARC1`` (case-insensitive).
        - The record must contain an exact ``p`` tag.

        Args:
            content: The TXT record string.

        Returns:
            bool: True if the record is a valid DMARC record, False otherwise.
        """
        tags = [t.strip() for t in content.split(";") if t.strip()]
        if not tags:
            return False
        # First tag must be v=DMARC1
        first_tag = tags[0]
        if "=" not in first_tag:
            return False
        tag_name, tag_value = first_tag.split("=", 1)
        if tag_name.strip().lower() != "v" or tag_value.strip() != "DMARC1":
            return False
        # Must contain an exact p tag
        for tag in tags[1:]:
            if "=" not in tag:
                continue
            name, _ = tag.split("=", 1)
            if name.strip().lower() == "p":
                return True
        return False

    def _get_policy_value(self, content):
        """
        Extract the DMARC policy value (reject, quarantine, or none) from a DMARC record.

        Validates exact tag boundaries so that tags like ``sp``, ``adkim``,
        or ``rua`` are not mistaken for the ``p`` (policy) tag, and enforces
        that the ``p`` tag appears exactly once.

        Args:
            content: The DMARC record string.

        Returns:
            str: The policy value ("reject", "quarantine", "none") or empty string if not found.
        """
        # Match the 'p' tag with exact tag boundaries: preceded by ';' or
        # start-of-string, and the value terminated by ';' or end-of-string.
        # [a-zA-Z]+ captures only the tag value (no semicolons or separators).
        matches = re.findall(
            r"(?:^|;)\s*p\s*=\s*([a-zA-Z]+)\s*(?:;|$)",
            content,
            re.IGNORECASE,
        )
        if len(matches) == 1:
            return matches[0].lower()
        elif len(matches) > 1:
            # Cardinality violation: 'p' tag appears more than once.
            return ""
        return ""
