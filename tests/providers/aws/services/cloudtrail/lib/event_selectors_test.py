from prowler.providers.aws.services.cloudtrail.cloudtrail_service import (
    Event_Selector,
    Trail,
)
from prowler.providers.aws.services.cloudtrail.lib.event_selectors import (
    data_event_resource_types,
    trail_data_event_coverage,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1

MEMORY_RESOURCE_TYPE = "AWS::BedrockAgentCore::Memory"
RUNTIME_RESOURCE_TYPE = "AWS::BedrockAgentCore::Runtime"
MEMORY_SELECTOR = {
    "Name": "AgentCore Memory data events",
    "FieldSelectors": [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
    ],
}


class Test_data_event_resource_types:
    def test_data_selector_covers_its_resource_type(self):
        """A plain data selector reports its resource type as completely covered."""
        assert data_event_resource_types(MEMORY_SELECTOR) == (
            {MEMORY_RESOURCE_TYPE},
            set(),
        )

    def test_several_resource_types_in_one_selector(self):
        """Every resource type of a multi-valued resources.type is credited.

        AWS rejects this shape on a real trail, but reading it back must not silently
        credit only the first value.
        """
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {
                        "Field": "resources.type",
                        "Equals": [MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE],
                    },
                ]
            }
        ) == ({MEMORY_RESOURCE_TYPE, RUNTIME_RESOURCE_TYPE}, set())

    def test_management_selector_covers_no_data_events(self):
        """A Management selector credits nothing, even when it names a resource type."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Management"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                ]
            }
        ) == (set(), set())

    def test_selector_without_event_category_covers_nothing(self):
        """A selector that never says eventCategory Data credits nothing."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]}
                ]
            }
        ) == (set(), set())

    def test_selector_without_field_selectors_covers_nothing(self):
        """A selector with no FieldSelectors key at all is read without raising."""
        assert data_event_resource_types({"Name": "empty"}) == (set(), set())

    def test_event_name_filter_narrows_coverage(self):
        """An eventName filter moves the resource type from complete to narrowed."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Field": "eventName", "Equals": ["ListEvents"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_read_only_filter_narrows_coverage(self):
        """A readOnly filter narrows coverage: write events are left unlogged."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Field": "readOnly", "Equals": ["true"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_resource_arn_filter_narrows_coverage(self):
        """A resources.ARN filter narrows coverage, including via StartsWith.

        The operator is not always ``Equals``, so the narrowing test cannot key on it.
        """
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {
                        "Field": "resources.ARN",
                        "StartsWith": [
                            "arn:aws:bedrock-agentcore:us-east-1:1:memory/x"
                        ],
                    },
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})

    def test_field_selector_without_a_field_narrows_coverage(self):
        """An unrecognizable filter has an unknown effect, not no effect."""
        assert data_event_resource_types(
            {
                "FieldSelectors": [
                    {"Field": "eventCategory", "Equals": ["Data"]},
                    {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                    {"Equals": ["something"]},
                ]
            }
        ) == (set(), {MEMORY_RESOURCE_TYPE})


class Test_trail_data_event_coverage:
    def test_every_selected_resource_type_is_reported(self):
        """Coverage is reported per resource type, AgentCore or not."""
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {"Field": "resources.type", "Equals": ["AWS::S3::Object"]},
                        ]
                    },
                ),
            ],
        )

        assert trail_data_event_coverage(trail) == (
            {MEMORY_RESOURCE_TYPE, "AWS::S3::Object"},
            set(),
        )

    def test_classic_selectors_are_not_credited(self):
        """Basic event selectors carry only DynamoDB, Lambda and S3 resource types."""
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(
                    is_advanced=False,
                    event_selector={
                        "ReadWriteType": "All",
                        "IncludeManagementEvents": True,
                        "DataResources": [
                            {
                                "Type": MEMORY_RESOURCE_TYPE,
                                "Values": ["arn:aws:bedrock-agentcore"],
                            }
                        ],
                    },
                )
            ],
        )

        assert trail_data_event_coverage(trail) == (
            set(),
            set(),
        )

    def test_complete_coverage_is_not_also_reported_as_narrowed(self):
        """One complete selector settles the type even when a narrowed one also matches.

        Otherwise a trail that logs everything would still be reported as partially
        covered because of a second, narrower selector.
        """
        narrowed_selector = {
            "FieldSelectors": [
                {"Field": "eventCategory", "Equals": ["Data"]},
                {"Field": "resources.type", "Equals": [MEMORY_RESOURCE_TYPE]},
                {"Field": "readOnly", "Equals": ["true"]},
            ]
        }
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=narrowed_selector),
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
            ],
        )

        assert trail_data_event_coverage(trail) == (
            {MEMORY_RESOURCE_TYPE},
            set(),
        )

    def test_narrowed_coverage_of_one_type_and_complete_of_another(self):
        """Coverage is tracked per resource type, not collapsed to one verdict per trail."""
        trail = Trail(
            region=AWS_REGION_US_EAST_1,
            name="trail_test",
            data_events=[
                Event_Selector(is_advanced=True, event_selector=MEMORY_SELECTOR),
                Event_Selector(
                    is_advanced=True,
                    event_selector={
                        "FieldSelectors": [
                            {"Field": "eventCategory", "Equals": ["Data"]},
                            {
                                "Field": "resources.type",
                                "Equals": [RUNTIME_RESOURCE_TYPE],
                            },
                            {"Field": "eventName", "Equals": ["InvokeAgentRuntime"]},
                        ]
                    },
                ),
            ],
        )

        assert trail_data_event_coverage(trail) == (
            {MEMORY_RESOURCE_TYPE},
            {RUNTIME_RESOURCE_TYPE},
        )
