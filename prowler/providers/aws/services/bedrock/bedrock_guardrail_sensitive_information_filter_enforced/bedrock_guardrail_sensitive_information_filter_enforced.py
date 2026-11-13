from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client

ENFORCING_ACTIONS = {"BLOCK", "ANONYMIZE"}


class bedrock_guardrail_sensitive_information_filter_enforced(Check):
    """Ensure guardrail sensitive-information entries block or mask matches on the output path.

    A guardrail can carry a full sensitive-information policy whose every PII entity and regex is
    set to NONE, which detects the match and returns it in the trace while still delivering the
    value to the caller. Presence of the policy therefore does not establish that leakage is
    stopped, which is all bedrock_guardrail_sensitive_information_filter_enabled asserts.

    Scope: guardrails that already carry a sensitive-information policy. A guardrail with no such
    policy is the subject of bedrock_guardrail_sensitive_information_filter_enabled and is not
    reported here.

    PASS when every entry blocks or masks its matches on the output path.
    FAIL when any entry takes no action on the output path, or has output evaluation switched off.
    MANUAL when the guardrail configuration could not be read, or an entry's action was not
    reported AND no other entry was proven unenforced. A proven leak outranks an incomplete
    inventory: this is a universal claim, so one entry known to take no action settles it.
    Unreported entries are still named in the FAIL text, so an incomplete inventory is disclosed
    rather than dropped.

    ENFORCING_ACTIONS holds only BLOCK and ANONYMIZE. NONE reports the detection in the trace and
    lets the content through, so an entry set to NONE detects a leak and permits it.

    Both name lists are rendered into status_extended, and they are built in the order GetGuardrail
    returned piiEntities and regexes. Neither ListGuardrails nor GetGuardrail documents an ordering,
    so each render point sorts independently: unsorted output makes one unchanged guardrail produce
    two different status_extended strings across scans, which reads as a changed finding.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        for guardrail in bedrock_client.guardrails.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=guardrail)

            if not guardrail.detail_retrieved:
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock Guardrail {guardrail.name} configuration could not be retrieved "
                    f"({guardrail.detail_error or 'unknown error'}); verify manually that its "
                    "sensitive information filters block or mask matches on the output path."
                )
                findings.append(report)
                continue

            if not guardrail.sensitive_information_entries:
                continue

            unreported = []
            unenforced = []
            for entry in guardrail.sensitive_information_entries:
                # GetGuardrail omits outputAction unless it was configured explicitly; the
                # required `action` governs the output path in that case.
                action = entry.output_action or entry.action
                if action is None:
                    unreported.append(entry.name)
                elif entry.output_enabled is False or action not in ENFORCING_ACTIONS:
                    unenforced.append(entry.name)

            if unenforced:
                unenforced.sort()
                unreported.sort()
                report.status = "FAIL"
                unreported_note = (
                    f" The action for {', '.join(unreported)} was not reported, so there may be "
                    "more."
                    if unreported
                    else ""
                )
                report.status_extended = (
                    f"Bedrock Guardrail {guardrail.name} detects but does not block or mask "
                    f"{', '.join(unenforced)} on the output path, so matched sensitive "
                    f"information still reaches the caller.{unreported_note}"
                )
            elif unreported:
                # Sorted here too: a second render point needs its own sort, not an inherited one.
                unreported.sort()
                report.status = "MANUAL"
                report.status_extended = (
                    f"Bedrock Guardrail {guardrail.name} did not report an action for "
                    f"{', '.join(unreported)}; verify manually that matches are blocked or "
                    "masked on the output path."
                )
            else:
                report.status = "PASS"
                count = len(guardrail.sensitive_information_entries)
                report.status_extended = (
                    f"Bedrock Guardrail {guardrail.name} blocks or masks "
                    f"{'its 1 configured sensitive information entry' if count == 1 else f'all {count} configured sensitive information entries'}"
                    " on the output path."
                )

            findings.append(report)

        return findings
