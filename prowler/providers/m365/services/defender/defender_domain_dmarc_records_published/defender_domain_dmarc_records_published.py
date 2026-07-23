from typing import List, Optional

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client


class defender_domain_dmarc_records_published(Check):
    """
    Check if DMARC records with an enforcement policy are published for all
    Exchange Online domains.

    Attributes:
        metadata: Metadata associated with the check (inherited from Check).
    """

    def execute(self) -> List[CheckReportM365]:
        """
        Execute the check to verify if DMARC records are published for all domains.

        This method inspects the DMARC DNS TXT record resolved for each domain
        (at ``_dmarc.<domain>``) and validates that an enforcement policy
        (``p=quarantine`` or ``p=reject``) is configured.

        Returns:
            List[CheckReportM365]: A list of reports containing the result of the check.
        """
        findings = []
        for (
            domain_id,
            domain,
        ) in defender_client.domain_dmarc_configurations.items():
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name=domain_id,
                resource_id=domain_id,
            )

            policy = self._get_dmarc_policy(domain.dmarc_record)

            if policy in ("quarantine", "reject"):
                report.status = "PASS"
                report.status_extended = f"DMARC record is published on Exchange Online for domain with ID {domain_id} with enforcement policy p={policy}."
            elif policy == "none":
                report.status = "FAIL"
                report.status_extended = f"DMARC record is published on Exchange Online for domain with ID {domain_id} but uses monitoring-only policy p=none."
            elif not domain.dmarc_record:
                report.status = "FAIL"
                report.status_extended = f"DMARC record is not published on Exchange Online for domain with ID {domain_id}."
            else:
                report.status = "FAIL"
                report.status_extended = f"DMARC record for domain with ID {domain_id} is malformed and does not include a valid enforcement policy."

            findings.append(report)

        return findings

    @staticmethod
    def _get_dmarc_policy(record: Optional[str]) -> Optional[str]:
        """
        Extract the DMARC policy (``p=``) tag value from a raw DMARC TXT record.

        Args:
            record: The raw ``_dmarc.<domain>`` TXT record content, or ``None``
                if no record was found.

        Returns:
            Optional[str]: The lowercase policy value (e.g. ``"reject"``), or
                ``None`` if the record is missing or malformed (does not start
                with ``v=DMARC1`` or has no ``p=`` tag).
        """
        if not record or not record.strip().lower().startswith("v=dmarc1"):
            return None

        for tag in record.split(";"):
            tag = tag.strip()
            if not tag or "=" not in tag:
                continue
            name, _, value = tag.partition("=")
            if name.strip().lower() == "p":
                return value.strip().lower()

        return None
