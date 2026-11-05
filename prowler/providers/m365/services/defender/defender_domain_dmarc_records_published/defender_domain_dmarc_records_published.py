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

        # If the Graph domain list could not be retrieved, an empty result means
        # the DMARC status is unknown for the tenant, not that it has no domains.
        if (
            not defender_client.domain_dmarc_configurations
            and defender_client.domain_discovery_failed
        ):
            report = CheckReportM365(
                metadata=self.metadata(),
                resource={},
                resource_name=defender_client.tenant_domain,
                resource_id=defender_client.tenant_domain,
            )
            report.status = "MANUAL"
            report.status_extended = "DMARC records could not be verified because the Exchange Online domain list could not be retrieved; manual review is required."
            findings.append(report)
            return findings

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

            if domain.lookup_failed:
                report.status = "MANUAL"
                report.status_extended = f"DMARC record for domain with ID {domain_id} could not be verified because the DNS lookup did not complete; manual review is required."
            elif policy in ("quarantine", "reject"):
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
                ``None`` if the record is missing or malformed. Per RFC 7489 the
                record must start with an exact ``v=DMARC1`` version tag and the
                ``p`` policy tag must immediately follow it.
        """
        if not record:
            return None

        tags = [tag.strip() for tag in record.split(";") if tag.strip()]
        if len(tags) < 2:
            return None

        # RFC 7489: the version tag MUST be first and equal to "DMARC1" exactly
        # (e.g. "v=DMARC10" is not a DMARC record).
        version_name, _, version_value = tags[0].partition("=")
        if version_name.strip().lower() != "v" or version_value.strip().lower() != (
            "dmarc1"
        ):
            return None

        # RFC 7489: the policy tag MUST immediately follow the version tag.
        policy_name, _, policy_value = tags[1].partition("=")
        if policy_name.strip().lower() != "p":
            return None

        return policy_value.strip().lower()
