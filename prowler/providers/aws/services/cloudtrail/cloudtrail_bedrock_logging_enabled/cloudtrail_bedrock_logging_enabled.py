from prowler.lib.check.models import Check, Check_Report_AWS
from prowler.providers.aws.services.cloudtrail.cloudtrail_client import (
    cloudtrail_client,
)
from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    Event_Selector,
)


class cloudtrail_bedrock_logging_enabled(Check):
    """Ensure CloudTrail is configured to log Amazon Bedrock API calls.

    This check verifies whether at least one CloudTrail trail is configured to
    capture Amazon Bedrock API calls through management events or advanced event
    selectors targeting Bedrock data events.

    - PASS: A trail logs Bedrock API calls via management events or Bedrock-specific advanced event selectors.
    - FAIL: No CloudTrail trail is configured to log Bedrock API calls.
    """

    # Bedrock resource types supported by CloudTrail advanced event selectors.
    BEDROCK_RESOURCE_TYPES = frozenset(
        {
            "AWS::Bedrock::AgentAlias",
            "AWS::Bedrock::FlowAlias",
            "AWS::Bedrock::Guardrail",
            "AWS::Bedrock::KnowledgeBase",
            "AWS::Bedrock::Model",
        }
    )

    def execute(self) -> list[Check_Report_AWS]:
        """Execute the check logic.

        Returns:
            A list of reports containing the result of the check.
        """
        findings = []
        if cloudtrail_client.trails is not None:
            for trail in cloudtrail_client.trails.values():
                if trail.is_logging:
                    for data_event in trail.data_events:
                        if self._logs_bedrock_events(data_event):
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=trail
                            )
                            report.region = trail.home_region
                            report.status = "PASS"
                            if data_event.is_advanced:
                                report.status_extended = f"Trail {trail.name} from home region {trail.home_region} has an advanced event selector to log Amazon Bedrock API calls."
                            else:
                                report.status_extended = f"Trail {trail.name} from home region {trail.home_region} has management events enabled to log Amazon Bedrock API calls."
                            findings.append(report)
                            break
            if not findings:
                report = Check_Report_AWS(
                    metadata=self.metadata(), resource=cloudtrail_client.trails
                )
                report.region = cloudtrail_client.region
                report.resource_arn = cloudtrail_client.trail_arn_template
                report.resource_id = cloudtrail_client.audited_account
                report.status = "FAIL"
                report.status_extended = "No CloudTrail trails are configured to log Amazon Bedrock API calls."
                findings.append(report)
        return findings

    def _logs_bedrock_events(self, data_event: Event_Selector) -> bool:
        """Check if an event selector captures Bedrock API calls.

        Args:
            data_event: An Event_Selector object from the trail.

        Returns:
            True if the event selector logs Bedrock events, False otherwise.
        """
        if not data_event.is_advanced:
            # Classic event selectors: management events include Bedrock
            # control-plane API calls when IncludeManagementEvents is True.
            return (
                data_event.event_selector.get("IncludeManagementEvents", False)
                and data_event.event_selector.get("ReadWriteType") == "All"
            )
        else:
            # Advanced event selectors: check for management events selector
            # or Bedrock-specific data event resource types.
            field_selectors = data_event.event_selector.get("FieldSelectors", [])

            for field in field_selectors:
                # Management events selector captures Bedrock control-plane calls.
                if field.get("Field") == "eventCategory" and "Management" in field.get(
                    "Equals", []
                ):
                    return True
                # Advanced data event selectors targeting Bedrock resources.
                if field.get("Field") == "resources.type":
                    for value in field.get("Equals", []):
                        if value in self.BEDROCK_RESOURCE_TYPES:
                            return True
            return False
