from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrock.bedrock_client import bedrock_client

REQUIRED_FILTER_TYPES = frozenset({"GROUNDING", "RELEVANCE"})
BLOCKING_ACTION = "BLOCK"


class bedrock_guardrail_contextual_grounding_filter_enabled(Check):
    """Ensure Bedrock guardrails block ungrounded and irrelevant model responses.

    - PASS: The guardrail configures both a GROUNDING and a RELEVANCE
      contextual grounding filter, each enabled, with action BLOCK and a
      threshold above 0.
    - FAIL: No contextual grounding policy is configured; one of the two
      required filter types is missing; a present filter carries
      enabled: false, so its evaluation never runs; a present filter uses
      action NONE, which scores and reports without blocking; or a present
      filter has a threshold of 0, which nothing can ever trip.
    - MANUAL: GetGuardrail failed, so the policy could not be retrieved and
      compliance cannot be asserted from an absent field; or a filter is
      otherwise compliant but omits enabled or action, leaving it unknown
      whether the evaluation runs or whether it blocks; or ListGuardrails failed
      for a Region, so that Region's guardrails are unknown rather than absent.

    enabled and action are both optional members of
    GuardrailContextualGroundingFilter (only type and threshold are required)
    and AWS documents no default for either, so an omitted value is unknown
    rather than false or NONE. Reading an omitted enabled as false would FAIL
    filters that are in fact evaluating; reading an omitted action as NONE
    would assert a misconfiguration the response never stated, and would print
    the literal None into status_extended where it reads as an AWS enum value.
    Both are therefore reported MANUAL, matching how this check already treats
    a guardrail whose detail could not be retrieved. An explicit enabled: false
    or an explicit non-BLOCK action is a definite finding and still FAILs, as
    does a zero threshold, so an unknown never masks a real one.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []

        for region, error in sorted(bedrock_client.guardrails_scan_errors.items()):
            report = Check_Report_AWS(
                metadata=self.metadata(), resource={"region": region}
            )
            report.region = region
            report.resource_id = "guardrail/unknown"
            report.resource_arn = f"arn:{bedrock_client.audited_partition}:bedrock:{region}:{bedrock_client.audited_account}:guardrail/unknown"
            report.status = "MANUAL"
            report.status_extended = f"Bedrock guardrails could not be listed in region {region} ({error}); verify manually that each one blocks ungrounded and irrelevant responses."
            findings.append(report)

        for guardrail in bedrock_client.guardrails.values():
            report = Check_Report_AWS(metadata=self.metadata(), resource=guardrail)

            if not guardrail.detail_retrieved:
                # GetGuardrail failed (permissions, throttling, transient
                # error). An absent policy is not evidence of a missing one.
                report.status = "MANUAL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} contextual grounding policy could not be retrieved in region {guardrail.region}; verify manually that GROUNDING and RELEVANCE filters block ungrounded responses."
                findings.append(report)
                continue

            filters_by_type = {
                filter.type: filter
                for filter in guardrail.contextual_grounding_filters
                if filter.type
            }

            if not filters_by_type:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} has no contextual grounding policy configured in region {guardrail.region}, so ungrounded and irrelevant responses are never detected."
                findings.append(report)
                continue

            missing_types = sorted(REQUIRED_FILTER_TYPES - set(filters_by_type))
            if missing_types:
                report.status = "FAIL"
                # Both required types can be missing at once, so the nouns follow
                # the count rather than assuming a single filter.
                noun = "filter" if len(missing_types) == 1 else "filters"
                classes = "that class" if len(missing_types) == 1 else "those classes"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} contextual grounding policy is missing the {', '.join(missing_types)} {noun} in region {guardrail.region}, leaving {classes} of ungrounded response unchecked."
                findings.append(report)
                continue

            reasons = []
            unknown_types = []
            for filter_type in sorted(REQUIRED_FILTER_TYPES):
                filter = filters_by_type[filter_type]
                action = filter.action
                if filter.enabled is False:
                    reasons.append(
                        f"the {filter_type} filter is disabled, so its evaluation never runs regardless of its action or threshold"
                    )
                elif action is not None and action != BLOCKING_ACTION:
                    reasons.append(
                        f"the {filter_type} filter uses action {action} instead of BLOCK, so it scores and reports without blocking"
                    )
                elif not (filter.threshold or 0) > 0:
                    reasons.append(
                        f"the {filter_type} filter has a threshold of {filter.threshold}, which no response can ever trip"
                    )
                elif action is None or filter.enabled is None:
                    # Name only the attributes actually omitted: one of the two
                    # may be present, and claiming both are missing describes a
                    # response the guardrail did not return.
                    missing = [
                        attribute
                        for attribute, value in (
                            ("enabled", filter.enabled),
                            ("action", action),
                        )
                        if value is None
                    ]
                    unknown_types.append(
                        f"{filter_type} filter omits {' and '.join(missing)}"
                    )

            if reasons:
                report.status = "FAIL"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} does not block ungrounded responses in region {guardrail.region}: {'; '.join(reasons)}."
            elif unknown_types:
                report.status = "MANUAL"
                subject = "it blocks" if len(unknown_types) == 1 else "they block"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} has both required contextual grounding filters with a non-zero threshold in region {guardrail.region}, but the {', '.join(unknown_types)}, so whether {subject} is unknown; verify manually that the evaluation runs and blocks."
            else:
                report.status = "PASS"
                report.status_extended = f"Bedrock Guardrail {guardrail.name} blocks ungrounded and irrelevant responses with GROUNDING and RELEVANCE filters in region {guardrail.region}."
            findings.append(report)

        return findings
