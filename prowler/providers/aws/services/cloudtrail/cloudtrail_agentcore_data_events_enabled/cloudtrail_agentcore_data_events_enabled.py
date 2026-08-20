from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    trail_data_event_coverage,
)

# The AWS::BedrockAgentCore::* resource types supported by CloudTrail data events.
AGENTCORE_RESOURCE_TYPES = frozenset(
    {
        "AWS::BedrockAgentCore::APIKeyCredentialProvider",
        "AWS::BedrockAgentCore::Browser",
        "AWS::BedrockAgentCore::BrowserCustom",
        "AWS::BedrockAgentCore::CodeInterpreter",
        "AWS::BedrockAgentCore::CodeInterpreterCustom",
        "AWS::BedrockAgentCore::Evaluator",
        "AWS::BedrockAgentCore::Gateway",
        "AWS::BedrockAgentCore::Memory",
        "AWS::BedrockAgentCore::OAuth2CredentialProvider",
        "AWS::BedrockAgentCore::Runtime",
        "AWS::BedrockAgentCore::RuntimeEndpoint",
        "AWS::BedrockAgentCore::TokenVault",
        "AWS::BedrockAgentCore::WorkloadIdentity",
        "AWS::BedrockAgentCore::WorkloadIdentityDirectory",
    }
)


class cloudtrail_agentcore_data_events_enabled(Check):
    """Ensure CloudTrail data events are enabled for Amazon Bedrock AgentCore.

    AgentCore data events carry the per-invocation, per-record and per-session activity of
    agents, memories, gateways and built-in tools. They are not logged by default and cannot
    be selected by a basic event selector, so an advanced event selector is the only way to
    capture them.

    - PASS: An actively logging trail selects every data event of at least one AgentCore
      resource type.
    - MANUAL: The event selectors of a trail could not be read, or the only AgentCore
      selectors also filter on other fields, so their coverage cannot be determined.
    - FAIL: No trail selects AgentCore data events.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if cloudtrail_client.trails is None:
            return findings

        undetermined_trails = []
        narrowed_trails = {}
        for trail in cloudtrail_client.trails.values():
            # Regions with no trail are held as a placeholder with no name; there is no trail
            # configuration to read there.
            if not trail.name:
                continue
            if trail.status_error or trail.event_selectors_error:
                undetermined_trails.append(trail.name)
                continue
            if not trail.is_logging:
                continue
            complete, narrowed = trail_data_event_coverage(
                trail, AGENTCORE_RESOURCE_TYPES
            )
            if complete:
                report = Check_Report_AWS(metadata=self.metadata(), resource=trail)
                report.region = trail.home_region
                report.status = "PASS"
                report.status_extended = (
                    f"Trail {trail.name} from home region {trail.home_region} has an "
                    "advanced data event selector for Amazon Bedrock AgentCore resource "
                    f"types {', '.join(sorted(complete))}."
                )
                findings.append(report)
            elif narrowed:
                narrowed_trails[trail.name] = narrowed

        if not findings:
            report = Check_Report_AWS(
                metadata=self.metadata(), resource=cloudtrail_client.trails
            )
            report.region = cloudtrail_client.region
            report.resource_arn = cloudtrail_client.trail_arn_template
            report.resource_id = cloudtrail_client.audited_account
            if narrowed_trails:
                report.status = "MANUAL"
                report.status_extended = (
                    "Trails "
                    f"{', '.join(sorted(narrowed_trails))} select Amazon Bedrock AgentCore "
                    "data events for resource types "
                    f"{', '.join(sorted(set().union(*narrowed_trails.values())))} but also "
                    "filter on other fields, so their coverage could not be determined."
                )
            elif undetermined_trails:
                report.status = "MANUAL"
                report.status_extended = (
                    "The event selectors of trails "
                    f"{', '.join(sorted(undetermined_trails))} could not be retrieved, so "
                    "Amazon Bedrock AgentCore data event coverage could not be determined."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "No CloudTrail trails have an advanced data event selector for Amazon "
                    "Bedrock AgentCore resource types."
                )
            findings.append(report)
        return findings
