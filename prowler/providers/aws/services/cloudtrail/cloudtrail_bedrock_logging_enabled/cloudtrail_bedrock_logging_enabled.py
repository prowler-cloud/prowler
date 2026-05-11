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
    capture Amazon Bedrock control-plane API calls through management events or
    Bedrock data events through advanced event selectors.

    - PASS: A trail logs Bedrock control-plane API calls via management events
      or Bedrock data events via Bedrock-specific advanced event selectors.
    - FAIL: No CloudTrail trail is configured to log Bedrock API calls.
    """

    # Bedrock resource types supported by CloudTrail advanced event selectors.
    BEDROCK_RESOURCE_TYPES = frozenset(
        {
            "AWS::Bedrock::AgentAlias",
            "AWS::Bedrock::FlowAlias",
            "AWS::Bedrock::Guardrail",
            "AWS::Bedrock::InlineAgent",
            "AWS::Bedrock::KnowledgeBase",
            "AWS::Bedrock::Model",
            "AWS::Bedrock::Prompt",
        }
    )
    BEDROCK_EVENT_SOURCES = frozenset(
        {
            "bedrock.amazonaws.com",
            "bedrock-agent.amazonaws.com",
            "bedrock-runtime.amazonaws.com",
            "bedrock-agent-runtime.amazonaws.com",
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
                        match_type = self._get_bedrock_match_type(data_event)
                        if match_type:
                            report = Check_Report_AWS(
                                metadata=self.metadata(), resource=trail
                            )
                            report.region = trail.home_region
                            report.status = "PASS"
                            if match_type == "classic_management":
                                report.status_extended = (
                                    f"Trail {trail.name} from home region "
                                    f"{trail.home_region} has management events "
                                    "enabled to log Amazon Bedrock control-plane "
                                    "API calls."
                                )
                            elif match_type == "advanced_management":
                                report.status_extended = (
                                    f"Trail {trail.name} from home region "
                                    f"{trail.home_region} has an advanced "
                                    "management event selector to log Amazon "
                                    "Bedrock control-plane API calls."
                                )
                            else:
                                report.status_extended = (
                                    f"Trail {trail.name} from home region "
                                    f"{trail.home_region} has an advanced data "
                                    "event selector to log Amazon Bedrock API "
                                    "calls."
                                )
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

    def _get_bedrock_match_type(self, data_event: Event_Selector) -> str | None:
        """Return the Bedrock logging match type for an event selector.

        Args:
            data_event: An Event_Selector object from the trail.

        Returns:
            The matching selector type, or None if the selector does not log
            the Bedrock events covered by this check.
        """
        if not data_event.is_advanced:
            if self._logs_classic_management_events(data_event.event_selector):
                return "classic_management"
            return None

        field_selectors = data_event.event_selector.get("FieldSelectors", [])
        if self._logs_advanced_management_events(field_selectors):
            return "advanced_management"
        if self._logs_advanced_bedrock_data_events(field_selectors):
            return "advanced_data"

        return None

    @staticmethod
    def _logs_classic_management_events(event_selector: dict) -> bool:
        """Check whether a classic selector logs Bedrock control-plane events."""
        return event_selector.get(
            "IncludeManagementEvents", False
        ) and event_selector.get("ReadWriteType") in ("All", "WriteOnly")

    def _logs_advanced_management_events(self, field_selectors: list[dict]) -> bool:
        """Check whether advanced selectors log Bedrock control-plane events."""
        event_category_selectors = [
            field for field in field_selectors if field.get("Field") == "eventCategory"
        ]
        if not self._selectors_match_value("Management", event_category_selectors):
            return False

        read_only_selectors = [
            field for field in field_selectors if field.get("Field") == "readOnly"
        ]
        has_read_only_restriction = bool(read_only_selectors) and not any(
            self._field_selector_matches_value("false", selector)
            for selector in read_only_selectors
        )

        return not has_read_only_restriction and self._logs_bedrock_management_events(
            field_selectors
        )

    def _logs_advanced_bedrock_data_events(self, field_selectors: list[dict]) -> bool:
        """Check whether advanced selectors log Bedrock data events."""
        event_category_selectors = [
            field for field in field_selectors if field.get("Field") == "eventCategory"
        ]
        if not self._selectors_match_value("Data", event_category_selectors):
            return False

        resource_type_selectors = [
            field for field in field_selectors if field.get("Field") == "resources.type"
        ]
        return any(
            self._selectors_match_value(resource_type, resource_type_selectors)
            for resource_type in self.BEDROCK_RESOURCE_TYPES
        )

    def _logs_bedrock_management_events(self, field_selectors: list[dict]) -> bool:
        """Check whether advanced management selectors include Bedrock sources."""
        event_source_selectors = [
            field for field in field_selectors if field.get("Field") == "eventSource"
        ]
        if not event_source_selectors:
            return True

        return any(
            self._selectors_match_value(event_source, event_source_selectors)
            for event_source in self.BEDROCK_EVENT_SOURCES
        )

    def _selectors_match_value(self, value: str, selectors: list[dict]) -> bool:
        """Check whether a candidate value satisfies all selectors for a field."""
        return bool(selectors) and all(
            self._field_selector_matches_value(value, selector)
            for selector in selectors
        )

    @staticmethod
    def _field_selector_matches_value(value: str, selector: dict) -> bool:
        """Evaluate a CloudTrail advanced field selector against a candidate value."""
        conditions = []

        if "Equals" in selector:
            conditions.append(value in selector["Equals"])
        if "NotEquals" in selector:
            conditions.append(value not in selector["NotEquals"])
        if "StartsWith" in selector:
            conditions.append(
                any(value.startswith(prefix) for prefix in selector["StartsWith"])
            )
        if "NotStartsWith" in selector:
            conditions.append(
                all(
                    not value.startswith(prefix) for prefix in selector["NotStartsWith"]
                )
            )
        if "EndsWith" in selector:
            conditions.append(
                any(value.endswith(suffix) for suffix in selector["EndsWith"])
            )
        if "NotEndsWith" in selector:
            conditions.append(
                all(not value.endswith(suffix) for suffix in selector["NotEndsWith"])
            )

        return all(conditions) if conditions else True
