from types import SimpleNamespace
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
MEMORY = "AWS::BedrockAgentCore::Memory"
GATEWAY = "AWS::BedrockAgentCore::Gateway"
RUNTIME = "AWS::BedrockAgentCore::Runtime"
RUNTIME_ENDPOINT = "AWS::BedrockAgentCore::RuntimeEndpoint"
INVENTORIES = (
    "memories",
    "gateways",
    "agent_runtimes",
    "code_interpreters",
    "browsers",
)


def _resource(kind, owner=AWS_ACCOUNT_NUMBER):
    """An AgentCore inventory entry; only its ARN is read by the check."""
    return SimpleNamespace(
        arn=f"arn:aws:bedrock-agentcore:{AWS_REGION_US_EAST_1}:{owner}:{kind}/example"
    )


def _agentcore(scan_errors=(), **inventories):
    """A mocked AgentCore client holding the given resources per inventory."""
    agentcore = mock.MagicMock()
    agentcore.audited_account = AWS_ACCOUNT_NUMBER
    for inventory in INVENTORIES:
        resources = inventories.get(inventory, [])
        setattr(agentcore, inventory, {r.arn: r for r in resources})
        setattr(
            agentcore,
            f"{inventory}_scan_errors",
            {AWS_REGION_US_EAST_1: "AccessDenied"} if inventory in scan_errors else {},
        )
    return agentcore


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


def _run_check(agentcore=None, mutate_service=None, scan_unused_services=False):
    """Build the service against the mocked account and execute the check.

    By default the account runs one AgentCore memory, so Memory coverage is required.
    """
    from prowler.providers.aws.services.cloudtrail.cloudtrail_service import Cloudtrail

    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1], scan_unused_services=scan_unused_services
    )
    service = Cloudtrail(aws_provider)
    if mutate_service:
        mutate_service(service)

    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK_MODULE_PATH}.cloudtrail_client", new=service),
        mock.patch(
            f"{CHECK_MODULE_PATH}.bedrockagentcore_client",
            new=agentcore or _agentcore(memories=[_resource("memory")]),
        ),
    ):
        from prowler.providers.aws.services.cloudtrail.cloudtrail_agentcore_data_events_enabled.cloudtrail_agentcore_data_events_enabled import (
            cloudtrail_agentcore_data_events_enabled,
        )

        return cloudtrail_agentcore_data_events_enabled().execute()


def _mark_trails(attribute, names=None):
    """Return a service mutator setting ``attribute`` on the named (or all) trails."""

    def mutate(service):
        for trail in service.trails.values():
            if trail.name and (names is None or trail.name in names):
                setattr(trail, attribute, "ClientError")

    return mutate


def _assert_account_level(finding):
    assert finding.resource_id == AWS_ACCOUNT_NUMBER
    assert (
        finding.resource_arn
        == f"arn:aws:cloudtrail:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:trail"
    )
    assert finding.region == AWS_REGION_US_EAST_1


class Test_cloudtrail_agentcore_data_events_enabled:
    @mock_aws
    def test_no_agentcore_resources(self):
        """No AgentCore in the account: nothing to log, nothing to report."""
        assert _run_check(agentcore=_agentcore()) == []

    @mock_aws
    def test_only_aws_owned_tools(self):
        """The SYSTEM code interpreter and browser exist everywhere and are not usage."""
        agentcore = _agentcore(
            code_interpreters=[_resource("code-interpreter", owner="aws")],
            browsers=[_resource("browser", owner="aws")],
        )

        assert _run_check(agentcore=agentcore) == []

    @mock_aws
    def test_no_agentcore_resources_scan_unused_services_no_trails(self):
        """Scanning unused services falls back to requiring any AgentCore type."""
        result = _run_check(agentcore=_agentcore(), scan_unused_services=True)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == "No actively logging CloudTrail trail logs Amazon Bedrock AgentCore data events."
        )
        _assert_account_level(result[0])

    @mock_aws
    def test_no_agentcore_resources_scan_unused_services_any_type_passes(self):
        _create_trail(advanced_event_selectors=[_data_selector(RUNTIME)])

        result = _run_check(agentcore=_agentcore(), scan_unused_services=True)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_memory_in_use_no_trails(self):
        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "No actively logging CloudTrail trail logs Amazon Bedrock AgentCore data "
            f"events for resource types {MEMORY}, which this account uses."
        )
        _assert_account_level(result[0])

    @mock_aws
    def test_memory_in_use_and_logged(self):
        _create_trail(
            advanced_event_selectors=[
                _data_selector(MEMORY),
                _data_selector(RUNTIME),
                _data_selector("AWS::S3::Object"),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].status_extended == (
            f"Trail {TRAIL_NAME} from home region {AWS_REGION_US_EAST_1} logs Amazon "
            f"Bedrock AgentCore data events for resource types {MEMORY}, {RUNTIME}."
        )
        assert result[0].resource_id == TRAIL_NAME
        assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_partial_coverage_names_the_missing_type(self):
        """Logging Memory does not cover the Gateway the account also runs."""
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY)])
        agentcore = _agentcore(
            memories=[_resource("memory")], gateways=[_resource("gateway")]
        )

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert result[0].status_extended == (
            "No actively logging CloudTrail trail logs Amazon Bedrock AgentCore data "
            f"events for resource types {GATEWAY}, which this account uses."
        )

    @mock_aws
    def test_coverage_spread_across_trails(self):
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY)])
        _create_trail(
            trail_name="trail_gateway",
            bucket_name="bucket_gateway",
            advanced_event_selectors=[_data_selector(GATEWAY)],
        )
        agentcore = _agentcore(
            memories=[_resource("memory")], gateways=[_resource("gateway")]
        )

        result = _run_check(agentcore=agentcore)

        assert sorted(r.status for r in result) == ["PASS", "PASS"]
        assert {r.resource_id for r in result} == {TRAIL_NAME, "trail_gateway"}

    @mock_aws
    def test_runtime_covered_by_runtime_endpoint(self):
        _create_trail(advanced_event_selectors=[_data_selector(RUNTIME_ENDPOINT)])
        agentcore = _agentcore(agent_runtimes=[_resource("runtime")])

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_custom_code_interpreter_needs_the_custom_type(self):
        """The built-in CodeInterpreter type does not log a custom interpreter."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector("AWS::BedrockAgentCore::CodeInterpreter")
            ]
        )
        agentcore = _agentcore(code_interpreters=[_resource("code-interpreter")])

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "AWS::BedrockAgentCore::CodeInterpreterCustom" in (
            result[0].status_extended
        )

    @mock_aws
    def test_custom_browser_logged(self):
        _create_trail(
            advanced_event_selectors=[
                _data_selector("AWS::BedrockAgentCore::BrowserCustom")
            ]
        )
        agentcore = _agentcore(browsers=[_resource("browser")])

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_selector_on_trail_not_logging(self):
        """A stopped trail records nothing, however its selectors are configured."""
        _create_trail(
            is_logging=False, advanced_event_selectors=[_data_selector(MEMORY)]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_non_agentcore_data_events_only(self):
        _create_trail(advanced_event_selectors=[_data_selector("AWS::S3::Object")])

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_management_events_only(self):
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
                        {"Type": MEMORY, "Values": ["arn:aws:bedrock-agentcore"]}
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
                    MEMORY, [{"Field": "eventName", "Equals": ["ListEvents"]}]
                )
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: trails "
            f"{TRAIL_NAME} log {MEMORY} only for a filtered subset of events."
        )
        _assert_account_level(result[0])

    @mock_aws
    def test_selector_narrowed_by_resource_arn(self):
        _create_trail(
            advanced_event_selectors=[
                _data_selector(
                    MEMORY,
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
        _create_trail(
            advanced_event_selectors=[
                _data_selector(MEMORY, [{"Field": "readOnly", "Equals": ["true"]}]),
                _data_selector(MEMORY),
            ]
        )

        result = _run_check()

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_narrowed_type_on_one_trail_is_not_reported_when_missing_type_is_definite(
        self,
    ):
        """A narrowed Memory selector does not hide that Gateway is not logged at all."""
        _create_trail(
            advanced_event_selectors=[
                _data_selector(MEMORY, [{"Field": "readOnly", "Equals": ["true"]}])
            ]
        )
        agentcore = _agentcore(
            memories=[_resource("memory")], gateways=[_resource("gateway")]
        )

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert GATEWAY in result[0].status_extended
        assert MEMORY not in result[0].status_extended

    @mock_aws
    def test_event_selectors_unreadable(self):
        _create_trail()

        result = _run_check(
            mutate_service=_mark_trails("event_selectors_error"),
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: the event "
            f"selectors of trails {TRAIL_NAME} could not be retrieved "
            "(cloudtrail:GetEventSelectors)."
        )

    @mock_aws
    def test_trail_status_unreadable(self):
        """GetTrailStatus failed: is_logging False is a default, not an answer."""
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY)])

        result = _run_check(mutate_service=_mark_trails("status_error"))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: the logging "
            f"status of trails {TRAIL_NAME} could not be retrieved "
            "(cloudtrail:GetTrailStatus)."
        )

    @mock_aws
    def test_stopped_trail_with_unreadable_selectors_still_fails(self):
        """A trail known to be stopped cannot cover AgentCore, so it cannot mask the FAIL."""
        _create_trail(is_logging=False)

        result = _run_check(mutate_service=_mark_trails("event_selectors_error"))

        assert len(result) == 1
        assert result[0].status == "FAIL"

    @mock_aws
    def test_both_read_failures_are_reported_separately(self):
        _create_trail()
        _create_trail(trail_name="trail_no_status", bucket_name="bucket_no_status")

        def deny_one_of_each(service):
            _mark_trails("event_selectors_error", {TRAIL_NAME})(service)
            _mark_trails("status_error", {"trail_no_status"})(service)

        result = _run_check(mutate_service=deny_one_of_each)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: the event "
            f"selectors of trails {TRAIL_NAME} could not be retrieved "
            "(cloudtrail:GetEventSelectors); the logging status of trails "
            "trail_no_status could not be retrieved (cloudtrail:GetTrailStatus)."
        )

    @mock_aws
    def test_unreadable_trail_does_not_mask_a_passing_trail(self):
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY)])
        _create_trail(trail_name="trail_unreadable", bucket_name="bucket_unreadable")

        result = _run_check(
            mutate_service=_mark_trails("event_selectors_error", {"trail_unreadable"})
        )

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert result[0].resource_id == TRAIL_NAME

    @mock_aws
    def test_trails_not_listed(self):
        """DescribeTrails denied account-wide is MANUAL, naming the permission."""
        result = _run_check(
            mutate_service=lambda service: setattr(service, "trails", None)
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: CloudTrail "
            "trails could not be retrieved. Verify that the scanning credentials are "
            "allowed to call cloudtrail:DescribeTrails."
        )
        _assert_account_level(result[0])

    @mock_aws
    def test_trails_partially_listed(self):
        """A Region whose trails could not be listed may hold the covering trail."""
        result = _run_check(
            mutate_service=lambda service: setattr(service, "trails_unavailable", True)
        )

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert "(cloudtrail:DescribeTrails)" in result[0].status_extended

    @mock_aws
    def test_inventory_not_listed_and_not_covered(self):
        """Memories could not be listed, so a missing Memory selector is undetermined."""
        result = _run_check(agentcore=_agentcore(scan_errors=("memories",)))

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert result[0].status_extended == (
            "Cannot evaluate Amazon Bedrock AgentCore data event logging: the AgentCore "
            f"resources behind {MEMORY} could not be listed (bedrock-agentcore:List*)."
        )

    @mock_aws
    def test_inventory_not_listed_but_covered(self):
        _create_trail(advanced_event_selectors=[_data_selector(MEMORY)])

        result = _run_check(agentcore=_agentcore(scan_errors=("memories",)))

        assert len(result) == 1
        assert result[0].status == "PASS"

    @mock_aws
    def test_inventory_error_in_one_region_does_not_hide_a_found_resource(self):
        """A memory found anywhere makes Memory required, not undetermined."""
        agentcore = _agentcore(
            scan_errors=("memories",), memories=[_resource("memory")]
        )

        result = _run_check(agentcore=agentcore)

        assert len(result) == 1
        assert result[0].status == "FAIL"
