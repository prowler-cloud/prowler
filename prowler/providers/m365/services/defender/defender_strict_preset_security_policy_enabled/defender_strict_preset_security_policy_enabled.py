from typing import List

from prowler.lib.check.models import Check, CheckReportM365
from prowler.providers.m365.services.defender.defender_client import defender_client

STRICT_PRESET_NAME = "Strict Preset Security Policy"


class defender_strict_preset_security_policy_enabled(Check):
    """Check if the Strict Preset Security Policy is enabled for EOP and Defender.

    The Strict Preset Security Policy applies Microsoft's recommended strict
    protection settings. It should be enabled for both Exchange Online Protection
    (anti-phishing, anti-spam, anti-malware) and Defender for Office 365 (Safe
    Attachments, Safe Links). A rule with no recipient conditions applies to all
    recipients.

    - PASS: The Strict Preset Security Policy is enabled for both EOP and Defender.
    - FAIL: The Strict Preset Security Policy is not enabled for EOP and/or Defender.
    """

    def _has_enabled_strict_preset(self, rules) -> bool:
        """Check whether any rule enables the Strict Preset Security Policy.

        A rule qualifies when it is named the Strict Preset Security Policy and is
        in the ``Enabled`` state. Recipient conditions are not evaluated because
        empty conditions mean the rule applies to all recipients.

        Args:
            rules: Iterable of preset security policy rules (EOP or ATP).

        Returns:
            bool: True if at least one rule enables the Strict Preset Security
            Policy, False otherwise.
        """
        return any(
            rule.name == STRICT_PRESET_NAME and rule.state == "Enabled"
            for rule in rules
        )

    def execute(self) -> List[CheckReportM365]:
        """Execute the Strict Preset Security Policy check.

        Evaluates whether the Strict Preset Security Policy is enabled for both
        Exchange Online Protection (EOP) and Defender for Office 365 (ATP),
        producing PASS only when both are enabled. Returns no findings when the
        policy rules could not be collected.

        Returns:
            List[CheckReportM365]: A list with the check report, or empty when the
            preset policy rules are unavailable.
        """
        findings = []
        eop_rules = defender_client.eop_protection_policy_rules
        atp_rules = defender_client.atp_protection_policy_rules
        if eop_rules is None or atp_rules is None:
            return findings

        report = CheckReportM365(
            metadata=self.metadata(),
            resource={
                "eop": [rule.dict() for rule in eop_rules],
                "atp": [rule.dict() for rule in atp_rules],
            },
            resource_name="Strict Preset Security Policy",
            resource_id="strictPresetSecurityPolicy",
        )

        eop_enabled = self._has_enabled_strict_preset(eop_rules)
        atp_enabled = self._has_enabled_strict_preset(atp_rules)

        if eop_enabled and atp_enabled:
            report.status = "PASS"
            report.status_extended = (
                "The Strict Preset Security Policy is enabled for both Exchange "
                "Online Protection and Defender for Office 365."
            )
        else:
            missing = []
            if not eop_enabled:
                missing.append("Exchange Online Protection")
            if not atp_enabled:
                missing.append("Defender for Office 365")
            report.status = "FAIL"
            report.status_extended = (
                "The Strict Preset Security Policy is not enabled for "
                f"{' or '.join(missing)}."
            )

        findings.append(report)
        return findings
