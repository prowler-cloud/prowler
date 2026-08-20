from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE_PATH = "prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_data_events_enabled.cloudtrail_agentcore_data_events_enabled"

TRAIL_NAME = "trail_test"
BUCKET_NAME = "bucket_test"


def _data_selector(resource_type, extra_field_selectors=None):
    """Build an advanced data event selector for one resources.type."""
    field_selectors = [
        {"Field": "eventCategory", "Equals": ["Data"]},
        {"Field": "resources.type", "Equals": [resource_type]},
    ]
    field_selectors.extend(extra_field_selectors or [])
    return {"Name": f"selector for {resource_type}", "FieldSelectors": field_selectors}


def _create_trail(
    trail_name=TRAIL_NAME,
    bucket_name=BUCKET_NAME,
    is_logging=True,
    advanced_event_selectors=None,
    event_selectors=None,
):
    """Create a trail in us-east-1 with the given selectors."""
    cloudtrail = client("cloudtrail", region_name=AWS_REGION_US_EAST_1)
    client("s3", region_name=AWS_REGION_US_EAST_1).create_bucket(Bucket=bucket_name)
    cloudtrail.create_trail(
        Name=trail_name, S3BucketName=bucket_name, IsMultiRegionTrail=False
    )
    if advanced_event_selectors:
        cloudtrail.put_event_selectors(
            TrailName=trail_name, AdvancedEventSelectors=advanced_event_selectors
        )
    elif event_selectors:
        cloudtrail.put_event_selectors(
            TrailName=trail_name, EventSelectors=event_selectors
        )
    if is_logging:
        cloudtrail.start_logging(Name=trail_name)


def _run_check(mutate_service=None):
    """Build the service against the mocked account and execute the check."""
    from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail

    aws_provider = set_mocked_aws_provider()
    service = Cloudtrail(aws_provider)
    if mutate_service:
        mutate_service(service)

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE_PATH}.cloudtrail_client", new=service),
    ):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_data_events_enabled.cloudtrail_agentcore_data_events_enabled import (
            cloudtrail_agentcore_data_events_enabled,
        )

        return cloudtrail_agentcore_data_events_enabled().execute()


class Test_cloudtrail_agentcore_data_events_enabled:
    @mock_aws
    def test_no_trails(self):
        """No trail at all: AgentCore data events cannot be logged."""
        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudTrail trails have an advanced data event selector for Amazon Bedrock AgentCore resource types."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER
        assert (
            result[0].resource_arn
            == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
        )
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_trails_unreadable(self):
        """DescribeTrails denied account-wide: nothing to report on."""
        result = _run_check(
            mutate_service=lambda service: setattr(service, "trails", None)
        )

        assert result == []

    @mock_aws
    def test_agentcore_runtime_data_events(self):
        """A Runtime data event selector on a logging trail passes."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector("AWS::BedrockAgentCore::Runtime"),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Trail {TRAIL_NAME} from home region {AWS_REGION_US_EAST_1} has an advanced "
            "data event selector for Amazon Bedrock AgentCore resource types "
            "AWS::BedrockAgentCore::Runtime."
        )
        assert result[0].resource_id == TRAIL_NAME
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_agentcore_multiple_resource_types_reported_sorted(self):
        """Every covered AgentCore type is named, in sorted order."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector("AWS::BedrockAgentCore::Runtime"),
                _data_selector("AWS::BedrockAgentCore::Memory"),
                _data_selector("AWS::S3::Object"),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Trail {TRAIL_NAME} from home region {AWS_REGION_US_EAST_1} has an advanced "
            "data event selector for Amazon Bedrock AgentCore resource types "
            "AWS::BedrockAgentCore::Memory, AWS::BedrockAgentCore::Runtime."
        )

    @mock_aws
    def test_agentcore_selector_on_trail_not_logging(self):
        """A stopped trail records nothing, however its selectors are configured."""
        _create_trail(
            is_logging=False,
            advanced_event_selectors=[_data_selector("AWS::BedrockAgentCore::Memory")],
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudTrail trails have an advanced data event selector for Amazon Bedrock AgentCore resource types."
        )

    @mock_aws
    def test_non_agentcore_data_events_only(self):
        """S3 data events do not cover AgentCore."""
        _create_trail(advanced_event_selectors=[_data_selector("AWS::S3::Object")])

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_management_events_only(self):
        """Management events are exactly what this check says are not enough."""
        _create_trail(
            advanced_event_selectors=[
                {
                    "Name": "management",
                    "FieldSelectors": [
                        {"Field": "eventCategory", "Equals": ["Management"]}
                    ],
                }
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_classic_selector_cannot_cover_agentcore(self):
        """A basic event selector supports only DynamoDB, Lambda and S3 resource types."""
        _create_trail(
            event_selectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": "AWS::BedrockAgentCore::Memory",
                            "Values": ["arn:aws:bedrock-agentcore"],
                        }
                    ],
                }
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_selector_narrowed_by_event_name(self):
        """An eventName filter leaves unknown coverage, which is not a pass."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    "AWS::BedrockAgentCore::Runtime",
                    [{"Field": "eventName", "Equals": ["InvokeAgentRuntime"]}],
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Trails {TRAIL_NAME} select Amazon Bedrock AgentCore data events for resource "
            "types AWS::BedrockAgentCore::Runtime but also filter on other fields, so "
            "their coverage could not be determined."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_selector_narrowed_by_read_only(self):
        """readOnly true logs reads only, so write activity is still unlogged."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    "AWS::BedrockAgentCore::Memory",
                    [{"Field": "readOnly", "Equals": ["true"]}],
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "AWS::BedrockAgentCore::Memory" in result[0].status_extended

    @mock_aws
    def test_selector_narrowed_by_resource_arn(self):
        """An ARN-scoped selector covers only the resources it names."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    "AWS::BedrockAgentCore::Memory",
                    [
                        {
                            "Field": "resources.ARN",
                            "StartsWith": [
                                f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:memory/audited"
                            ],
                        }
                    ],
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_broad_selector_wins_over_narrowed_selector(self):
        """A type covered in full is not also reported as undetermined."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    "AWS::BedrockAgentCore::Memory",
                    [{"Field": "readOnly", "Equals": ["true"]}],
                ),
                _data_selector("AWS::BedrockAgentCore::Memory"),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended.endswith("AWS::BedrockAgentCore::Memory.")

    @mock_aws
    def test_event_selectors_unreadable(self):
        """GetEventSelectors failed: absence of a selector is not established."""
        _create_trail()

        def deny_selectors(service):
            for trail in service.trails.values():
                if trail.name:
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_selectors)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"The event selectors of trails {TRAIL_NAME} could not be retrieved, so Amazon "
            "Bedrock AgentCore data event coverage could not be determined."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_trail_status_unreadable(self):
        """GetTrailStatus failed: is_logging False is a default, not an answer."""
        _create_trail(
            advanced_event_selectors=[_data_selector("AWS::BedrockAgentCore::Memory")]
        )

        def deny_status(service):
            for trail in service.trails.values():
                if trail.name:
                    trail.status_error = "ClientError"

        result = _run_check(mutate_service=deny_status)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert TRAIL_NAME in result[0].status_extended

    @mock_aws
    def test_unreadable_trail_does_not_mask_a_passing_trail(self):
        """One trail proves the account logs AgentCore data events."""
        _create_trail(
            advanced_event_selectors=[_data_selector("AWS::BedrockAgentCore::Gateway")]
        )
        _create_trail(trail_name="trail_unreadable", bucket_name="bucket_unreadable")

        def deny_one(service):
            for trail in service.trails.values():
                if trail.name == "trail_unreadable":
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_one)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == TRAIL_NAME

    @mock_aws
    def test_narrowed_coverage_reported_before_unreadable_trail(self):
        """A configured but narrowed selector is the more specific finding."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    "AWS::BedrockAgentCore::Browser",
                    [{"Field": "eventName", "Equals": ["StartBrowserSession"]}],
                )
            ]
        )
        _create_trail(trail_name="trail_unreadable", bucket_name="bucket_unreadable")

        def deny_one(service):
            for trail in service.trails.values():
                if trail.name == "trail_unreadable":
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_one)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Trails {TRAIL_NAME} select Amazon Bedrock AgentCore data events for resource "
            "types AWS::BedrockAgentCore::Browser but also filter on other fields, so "
            "their coverage could not be determined."
        )

    @mock_aws
    def test_every_documented_agentcore_resource_type_passes(self):
        """Each of the 14 AgentCore data event resource types is recognized."""
        from prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_data_events_enabled.cloudtrail_agentcore_data_events_enabled import (
            AGENTCORE_RESOURCE_TYPES,
        )

        resource_types = sorted(AGENTCORE_RESOURCE_TYPES)
        assert resource_types == [
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
        ]

        _create_trail(
            advanced_event_selectors=[
                _data_selector(resource_type) for resource_type in resource_types
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        for resource_type in resource_types:
            assert resource_type in result[0].status_extended
