import re
from typing import List

import dns.resolver

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender import defender_client

DMARC_POLICY_RE = re.compile(
    r"(?:^|;)\s*p\s*=\s*(?P<policy>[^;\s]+)",
    re.IGNORECASE,
)


class defender_domain_dmarc_records_published(Check):
    """
    Check if Exchange Online domains publish enforcing DMARC records.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if DMARC is enforced for all domains.

        This method checks each domain from the DKIM signing configuration list
        for a DMARC TXT record with p=quarantine or p=reject.

        Returns:
            List[CheckReportM365]: A list of reports containing the result.
        """
        findings = []
        client = defender_client.defender_client
        for config in client.dkim_configurations:
            dmarc_policy = _get_dmarc_policy(config.id)

            report = CheckReportM365(
                metadata=self.metadata(),
                resource=config,
                resource_name=config.id,
                resource_id=config.id,
            )
            report.status = "FAIL"
            report.status_extended = (
                f"DMARC record for domain {config.id} is not published "
                "with an enforcing policy."
            )

            if dmarc_policy in ("quarantine", "reject"):
                report.status = "PASS"
                report.status_extended = (
                    f"DMARC record for domain {config.id} is published with "
                    f"enforcing policy p={dmarc_policy}."
                )

            findings.append(report)

        return findings


def _get_dmarc_policy(domain: str) -> str:
    try:
        txt_records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
    except dns.exception.DNSException:
        return ""

    for record in txt_records:
        txt_value = _txt_record_to_string(record)
        if "V=DMARC1" not in txt_value.upper():
            continue

        policy_match = DMARC_POLICY_RE.search(txt_value)
        if policy_match:
            return policy_match.group("policy").lower()

    return ""


def _txt_record_to_string(record) -> str:
    strings = getattr(record, "strings", None)
    if strings:
        return "".join(
            (
                chunk.decode("utf-8", errors="ignore")
                if isinstance(chunk, bytes)
                else str(chunk)
            )
            for chunk in strings
        )

    return str(record).strip('"')
