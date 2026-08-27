from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

CHECK_MODULE_PATH = "prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_memory_data_events_enabled.cloudtrail_agentcore_memory_data_events_enabled"

TRAIL_NAME = "trail_test"
BUCKET_NAME = "bucket_test"
MEMORY_RESOURCE_TYPE = "AWS::BedrockAgentCore::Memory"


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
        from prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_memory_data_events_enabled.cloudtrail_agentcore_memory_data_events_enabled import (
            cloudtrail_agentcore_memory_data_events_enabled,
        )

        return cloudtrail_agentcore_memory_data_events_enabled().execute()


class Test_cloudtrail_agentcore_memory_data_events_enabled:
    @mock_aws
    def test_no_trails(self):
        """No trail at all: Memory data events cannot be logged."""
        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudTrail trails have an advanced data event selector for Amazon Bedrock AgentCore Memory."
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
    def test_memory_data_events(self):
        """A Memory data event selector on a logging trail passes."""
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY_RESOURCE_TYPE)])

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Trail {TRAIL_NAME} from home region {AWS_REGION_US_EAST_1} has an advanced "
            "data event selector for Amazon Bedrock AgentCore Memory."
        )
        assert result[0].resource_id == TRAIL_NAME
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_other_agentcore_data_events_do_not_cover_memory(self):
        """Runtime and Gateway data events say nothing about memory records."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector("AWS::BedrockAgentCore::Runtime"),
                _data_selector("AWS::BedrockAgentCore::RuntimeEndpoint"),
                _data_selector("AWS::BedrockAgentCore::Gateway"),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudTrail trails have an advanced data event selector for Amazon Bedrock AgentCore Memory."
        )

    @mock_aws
    def test_memory_selector_on_trail_not_logging(self):
        """A stopped trail records nothing, however its selectors are configured."""
        _create_trail(
            is_logging=False,
            advanced_event_selectors=[_data_selector(MEMORY_RESOURCE_TYPE)],
        )

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
    def test_classic_selector_cannot_cover_memory(self):
        """A basic event selector supports only DynamoDB, Lambda and S3 resource types."""
        _create_trail(
            event_selectors=[
                {
                    "ReadWriteType": "All",
                    "IncludeManagementEvents": True,
                    "DataResources": [
                        {
                            "Type": MEMORY_RESOURCE_TYPE,
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
        """An eventName filter leaves the rest of the Memory data plane unlogged."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    MEMORY_RESOURCE_TYPE,
                    [{"Field": "eventName", "Equals": ["ListEvents"]}],
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Trails {TRAIL_NAME} select Amazon Bedrock AgentCore Memory data events but "
            "also filter on other fields, so their coverage could not be determined."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_selector_narrowed_by_read_only(self):
        """readOnly false logs writes only, so memory reads are still unlogged."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    MEMORY_RESOURCE_TYPE, [{"Field": "readOnly", "Equals": ["false"]}]
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"

    @mock_aws
    def test_selector_narrowed_by_resource_arn(self):
        """An ARN-scoped selector covers only the memories it names."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    MEMORY_RESOURCE_TYPE,
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
        """Memory covered in full is not also reported as undetermined."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    MEMORY_RESOURCE_TYPE, [{"Field": "readOnly", "Equals": ["false"]}]
                ),
                _data_selector(MEMORY_RESOURCE_TYPE),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_event_selectors_unreadable(self):
        """GetEventSelectors failed: absence of a selector is not established."""
        _create_trail()

        def deny_selectors(service):
            """Mark every named trail's event selectors as unreadable."""
            for trail in service.trails.values():
                if trail.name:
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_selectors)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Amazon Bedrock AgentCore Memory data event coverage could not be determined "
            f"because the event selectors of trails {TRAIL_NAME} could not be retrieved."
        )
        assert result[0].resource_id == AWS_ACCOUNT_NUMBER

    @mock_aws
    def test_trail_status_unreadable(self):
        """GetTrailStatus failed: is_logging False is a default, not an answer."""
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY_RESOURCE_TYPE)])

        def deny_status(service):
            """Mark every named trail's logging status as unreadable."""
            for trail in service.trails.values():
                if trail.name:
                    trail.status_error = "ClientError"

        result = _run_check(mutate_service=deny_status)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        # Attributed to the status read, not the selector read: the selectors were retrieved
        # here, and naming the wrong API sends the reader to the wrong permission.
        assert result[0].status_extended == (
            "Amazon Bedrock AgentCore Memory data event coverage could not be determined "
            f"because the logging status of trails {TRAIL_NAME} could not be retrieved."
        )

    @mock_aws
    def test_stopped_trail_with_unreadable_selectors_still_fails(self):
        """A trail known to be stopped cannot cover Memory, so it cannot mask the FAIL.

        The selector read failed, but the status read did not: the trail is definitively not
        logging, so whatever its selectors say it delivers nothing. Reporting MANUAL here
        would downgrade a definitive finding on the strength of an irrelevant unknown.
        """
        _create_trail(is_logging=False)

        def deny_selectors(service):
            """Mark the stopped trail's event selectors as unreadable."""
            for trail in service.trails.values():
                if trail.name:
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_selectors)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No CloudTrail trails have an advanced data event selector for Amazon Bedrock AgentCore Memory."
        )

    @mock_aws
    def test_both_read_failures_are_reported_separately(self):
        """Two trails failing two different reads are named under their own cause."""
        _create_trail()
        _create_trail(trail_name="trail_no_status", bucket_name="bucket_no_status")

        def deny_one_of_each(service):
            """Deny the selector read on one trail and the status read on the other."""
            for trail in service.trails.values():
                if trail.name == TRAIL_NAME:
                    trail.event_selectors_error = "ClientError"
                elif trail.name == "trail_no_status":
                    trail.status_error = "ClientError"

        result = _run_check(mutate_service=deny_one_of_each)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Amazon Bedrock AgentCore Memory data event coverage could not be determined "
            f"because the event selectors of trails {TRAIL_NAME} could not be retrieved; the "
            "logging status of trails trail_no_status could not be retrieved."
        )

    @mock_aws
    def test_unreadable_trail_does_not_mask_a_passing_trail(self):
        """One trail proves the account logs Memory data events."""
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY_RESOURCE_TYPE)])
        _create_trail(trail_name="trail_unreadable", bucket_name="bucket_unreadable")

        def deny_one(service):
            """Mark only trail_unreadable's event selectors as unreadable."""
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
                    MEMORY_RESOURCE_TYPE,
                    [{"Field": "eventName", "Equals": ["ListEvents"]}],
                )
            ]
        )
        _create_trail(trail_name="trail_unreadable", bucket_name="bucket_unreadable")

        def deny_one(service):
            """Mark only trail_unreadable's event selectors as unreadable."""
            for trail in service.trails.values():
                if trail.name == "trail_unreadable":
                    trail.event_selectors_error = "ClientError"

        result = _run_check(mutate_service=deny_one)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            f"Trails {TRAIL_NAME} select Amazon Bedrock AgentCore Memory data events but "
            "also filter on other fields, so their coverage could not be determined."
        )
