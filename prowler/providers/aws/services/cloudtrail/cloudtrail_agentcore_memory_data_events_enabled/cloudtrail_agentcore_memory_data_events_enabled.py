from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    trail_data_event_coverage,
)

# The CloudTrail data event resource type of the AgentCore Memory data plane.
MEMORY_RESOURCE_TYPES = frozenset({"AWS::BedrockAgentCore::Memory"})


class cloudtrail_agentcore_memory_data_events_enabled(Check):
    """Ensure CloudTrail data events are enabled for Amazon Bedrock AgentCore Memory.

    Management events show that a memory was created or deleted. Only the
    AWS::BedrockAgentCore::Memory data events show the per-record and per-event operations
    that reveal who read or wrote which memory, and they are not logged by default.

    - PASS: An actively logging trail selects every AWS::BedrockAgentCore::Memory data event.
    - MANUAL: The logging status or the event selectors of a trail could not be read, or the
      only Memory selectors also filter on other fields, so coverage cannot be determined.
    - FAIL: No actively logging trail selects AWS::BedrockAgentCore::Memory data events. A
      stopped trail cannot change that verdict, so an unreadable selector on one does not
      make it undetermined.
    """

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if cloudtrail_client.trails is None:
            return findings

        selectors_unknown_trails = []
        status_unknown_trails = []
        narrowed_trails = []
        for trail in cloudtrail_client.trails.values():
            # Regions with no trail are held as a placeholder with no name; there is no trail
            # configuration to read there.
            if not trail.name:
                continue
            # Status first: a failed GetTrailStatus leaves is_logging at its False default, so
            # the stopped-trail skip below would read that default as an answer.
            if trail.status_error:
                status_unknown_trails.append(trail.name)
                continue
            # A stopped trail delivers nothing, so it cannot be the trail that covers Memory
            # however its selectors are configured -- including when they could not be read.
            if not trail.is_logging:
                continue
            if trail.event_selectors_error:
                selectors_unknown_trails.append(trail.name)
                continue
            complete, narrowed = trail_data_event_coverage(trail, MEMORY_RESOURCE_TYPES)
            if complete:
                report = Check_Report_AWS(metadata=self.metadata(), resource=trail)
                report.region = trail.home_region
                report.status = "PASS"
                report.status_extended = (
                    f"Trail {trail.name} from home region {trail.home_region} has an "
                    "advanced data event selector for Amazon Bedrock AgentCore Memory."
                )
                findings.append(report)
            elif narrowed:
                narrowed_trails.append(trail.name)

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
                    f"Trails {', '.join(sorted(narrowed_trails))} select Amazon Bedrock "
                    "AgentCore Memory data events but also filter on other fields, so "
                    "their coverage could not be determined."
                )
            elif selectors_unknown_trails or status_unknown_trails:
                report.status = "MANUAL"
                # Named separately: a status read and a selector read fail for different
                # reasons, and reporting one as the other sends the reader to the wrong API.
                reasons = []
                if selectors_unknown_trails:
                    reasons.append(
                        "the event selectors of trails "
                        f"{', '.join(sorted(selectors_unknown_trails))} could not be "
                        "retrieved"
                    )
                if status_unknown_trails:
                    reasons.append(
                        "the logging status of trails "
                        f"{', '.join(sorted(status_unknown_trails))} could not be retrieved"
                    )
                report.status_extended = (
                    "Amazon Bedrock AgentCore Memory data event coverage could not be "
                    f"determined because {'; '.join(reasons)}."
                )
            else:
                report.status = "FAIL"
                report.status_extended = (
                    "No CloudTrail trails have an advanced data event selector for Amazon "
                    "Bedrock AgentCore Memory."
                )
            findings.append(report)
        return findings
