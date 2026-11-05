from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.bedrockagentcore.bedrockagentcore_client import (
    bedrockagentcore_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.lib.event_selectors import (
    trail_data_event_coverage,
)

AGENTCORE_TYPE_PREFIX = "AWS::BedrockAgentCore::"

# AgentCore inventory -> the data event resource types that record activity on it; any one
# of them satisfies the requirement. The AWS-owned SYSTEM code interpreter and browser exist
# in every AgentCore Region, so only account-owned (CUSTOM) ones count as deployed. Token
# vaults are left out: their presence does not show the account uses AgentCore Identity.
INVENTORY_REQUIREMENTS = (
    ("memories", "memories_scan_errors", ("AWS::BedrockAgentCore::Memory",)),
    ("gateways", "gateways_scan_errors", ("AWS::BedrockAgentCore::Gateway",)),
    (
        "agent_runtimes",
        "agent_runtimes_scan_errors",
        ("AWS::BedrockAgentCore::Runtime", "AWS::BedrockAgentCore::RuntimeEndpoint"),
    ),
    (
        "code_interpreters",
        "code_interpreters_scan_errors",
        ("AWS::BedrockAgentCore::CodeInterpreterCustom",),
    ),
    ("browsers", "browsers_scan_errors", ("AWS::BedrockAgentCore::BrowserCustom",)),
)


class cloudtrail_agentcore_data_events_enabled(Check):
    """Ensure CloudTrail logs data events for the Amazon Bedrock AgentCore resources in use.

    AgentCore data events record agent invocations, memory record operations, gateway tool
    calls and built-in tool sessions. They are not logged by default and only an advanced
    event selector can select them.

    - PASS: Actively logging trails select every data event of each AgentCore resource type
      the account runs (or of any AgentCore type, when scanning unused services).
    - MANUAL: A missing type might be covered by a narrowed selector, an unreadable trail or
      an AgentCore inventory that could not be listed.
    - FAIL: No actively logging trail selects data events for an AgentCore resource type the
      account runs.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        required, unknown = self._agentcore_requirements()
        if not required and not unknown:
            if not cloudtrail_client.provider.scan_unused_services:
                return findings
            # An empty tuple is met by any AgentCore resource type.
            required = [()]

        if cloudtrail_client.trails is None:
            report = self._account_report("MANUAL")
            report.status_extended = (
                "Cannot evaluate Amazon Bedrock AgentCore data event logging: CloudTrail "
                "trails could not be retrieved. Verify that the scanning credentials are "
                "allowed to call cloudtrail:DescribeTrails."
            )
            return [report]

        covered = set()
        narrowed = {}
        selectors_unknown_trails = []
        status_unknown_trails = []
        for trail in cloudtrail_client.trails.values():
            # Regions with no trail are held as a placeholder with no name.
            if not trail.name:
                continue
            # Status first: a failed GetTrailStatus leaves is_logging at its False default.
            if trail.status_error:
                status_unknown_trails.append(trail.name)
                continue
            # A stopped trail delivers nothing, whatever its selectors say.
            if not trail.is_logging:
                continue
            if trail.event_selectors_error:
                selectors_unknown_trails.append(trail.name)
                continue
            complete, partial = trail_data_event_coverage(trail)
            complete = {t for t in complete if t.startswith(AGENTCORE_TYPE_PREFIX)}
            partial = {t for t in partial if t.startswith(AGENTCORE_TYPE_PREFIX)}
            covered |= complete
            if partial:
                narrowed[trail.name] = partial
            if complete:
                report = Check_Report_AWS(metadata=self.metadata(), resource=trail)
                report.region = trail.home_region
                report.status = "PASS"
                report.status_extended = (
                    f"Trail {trail.name} from home region {trail.home_region} logs "
                    "Amazon Bedrock AgentCore data events for resource types "
                    f"{', '.join(sorted(complete))}."
                )
                findings.append(report)

        missing = [types for types in required if not _met(types, covered)]
        unknown_missing = [types for types in unknown if not _met(types, covered)]
        if not missing and not unknown_missing:
            return findings

        # A type logged in full by any trail is settled, whatever another trail narrows.
        narrowed = {
            name: types - covered for name, types in narrowed.items() if types - covered
        }
        narrowed_types = set().union(*narrowed.values())
        trails_unknown = (
            selectors_unknown_trails
            or status_unknown_trails
            or cloudtrail_client.trails_unavailable
        )
        definitely_missing = (
            []
            if trails_unknown
            else [types for types in missing if not _met(types, narrowed_types)]
        )

        # The partial PASS findings are replaced by one account-level verdict.
        if definitely_missing:
            report = self._account_report("FAIL")
            if definitely_missing == [()]:
                report.status_extended = (
                    "No actively logging CloudTrail trail logs Amazon Bedrock AgentCore "
                    "data events."
                )
            else:
                report.status_extended = (
                    "No actively logging CloudTrail trail logs Amazon Bedrock AgentCore "
                    "data events for resource types "
                    f"{_names(definitely_missing)}, which this account uses."
                )
            return [report]

        reasons = []
        if narrowed:
            reasons.append(
                f"trails {', '.join(sorted(narrowed))} log "
                f"{', '.join(sorted(narrowed_types))} only for a filtered subset of events"
            )
        if selectors_unknown_trails:
            reasons.append(
                "the event selectors of trails "
                f"{', '.join(sorted(selectors_unknown_trails))} could not be retrieved "
                "(cloudtrail:GetEventSelectors)"
            )
        if status_unknown_trails:
            reasons.append(
                "the logging status of trails "
                f"{', '.join(sorted(status_unknown_trails))} could not be retrieved "
                "(cloudtrail:GetTrailStatus)"
            )
        if cloudtrail_client.trails_unavailable:
            reasons.append(
                "trails could not be listed in every Region (cloudtrail:DescribeTrails)"
            )
        if unknown_missing:
            reasons.append(
                "the AgentCore resources behind "
                f"{_names(unknown_missing)} could not be listed "
                "(bedrock-agentcore:List*)"
            )
        report = self._account_report("MANUAL")
        report.status_extended = (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: "
            f"{'; '.join(reasons)}."
        )
        return [report]

    def _account_report(self, status: str) -> Check_Report_AWS:
        """Build an account-level report, used when no single trail carries the verdict."""
        report = Check_Report_AWS(metadata=self.metadata(), resource={})
        report.region = cloudtrail_client.region
        report.resource_arn = cloudtrail_client.trail_arn_template
        report.resource_id = cloudtrail_client.audited_account
        report.status = status
        return report

    @staticmethod
    def _agentcore_requirements() -> tuple[list[tuple], list[tuple]]:
        """Return the resource type requirements of the AgentCore resources in use.

        Returns:
            ``(required, unknown)``: the requirements of the resources found, and those of
            resource kinds that could not be listed in at least one Region and were not
            found elsewhere.
        """
        required = []
        unknown = []
        for inventory, scan_errors, types in INVENTORY_REQUIREMENTS:
            if any(
                resource.arn.split(":")[4] == bedrockagentcore_client.audited_account
                for resource in getattr(bedrockagentcore_client, inventory).values()
            ):
                required.append(types)
            elif getattr(bedrockagentcore_client, scan_errors):
                unknown.append(types)
        return required, unknown


def _met(types: tuple, covered: set) -> bool:
    """Whether a requirement is met; an empty requirement is met by any type."""
    return bool(covered.intersection(types)) if types else bool(covered)


def _names(requirements: list[tuple]) -> str:
    """Name each requirement by its first resource type."""
    return ", ".join(sorted(types[0] for types in requirements if types))
