import json
from unittest.mock import patch

import botocore
from botocore.exceptions import ClientError

from prowler.providers.aws.services.oam.oam_service import OAM, SinkPolicyState
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

make_api_call = botocore.client.BaseClient._make_api_call

SINK_PAGE_ONE_ARN = (
    f"arn:aws:oam:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:sink/page-one"
)
SINK_PAGE_TWO_ARN = (
    f"arn:aws:oam:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:sink/page-two"
)

ORGANIZATION_SINK_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": "*",
            "Action": ["oam:CreateLink", "oam:UpdateLink"],
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"}},
        }
    ],
}


def _list_sinks_pages(next_token):
    """ListSinks over two pages, so a first-page-only collector loses the second sink."""
    if next_token is None:
        return {
            "Items": [
                {"Arn": SINK_PAGE_ONE_ARN, "Id": "page-one", "Name": "sink-page-one"}
            ],
            "NextToken": "second-page",
        }
    return {
        "Items": [{"Arn": SINK_PAGE_TWO_ARN, "Id": "page-two", "Name": "sink-page-two"}]
    }


def mock_make_api_call(self, operation_name, kwarg):
    """Two sinks: the first carries an organization-scoped policy, the second has none."""
    if operation_name == "ListSinks":
        return _list_sinks_pages(kwarg.get("NextToken"))
    if operation_name == "GetSinkPolicy":
        if kwarg["SinkIdentifier"] == SINK_PAGE_TWO_ARN:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Policy not found",
                    }
                },
                operation_name,
            )
        return {
            "Policy": json.dumps(ORGANIZATION_SINK_POLICY),
            "SinkArn": SINK_PAGE_ONE_ARN,
            "SinkId": "page-one",
        }
    if operation_name == "ListTagsForResource":
        return {"Tags": {"environment": "production"}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_access_denied(self, operation_name, kwarg):
    """GetSinkPolicy is denied, so the policy cannot be read either way."""
    if operation_name == "ListSinks":
        return _list_sinks_pages(None)
    if operation_name == "GetSinkPolicy":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            operation_name,
        )
    if operation_name == "ListTagsForResource":
        return {"Tags": {}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_unparseable_policy(self, operation_name, kwarg):
    """GetSinkPolicy returns a Policy member that is not JSON at all."""
    if operation_name == "ListSinks":
        return _list_sinks_pages(None)
    if operation_name == "GetSinkPolicy":
        return {"Policy": "}not-json{", "SinkArn": SINK_PAGE_ONE_ARN}
    if operation_name == "ListTagsForResource":
        return {"Tags": {}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_empty_policy(self, operation_name, kwarg):
    """GetSinkPolicy succeeds but the Policy member is empty."""
    if operation_name == "ListSinks":
        return _list_sinks_pages(None)
    if operation_name == "GetSinkPolicy":
        return {"Policy": "", "SinkArn": SINK_PAGE_ONE_ARN}
    if operation_name == "ListTagsForResource":
        return {"Tags": {}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_scalar_policy(self, operation_name, kwarg):
    """GetSinkPolicy returns valid JSON that decodes to a string rather than an object."""
    if operation_name == "ListSinks":
        return _list_sinks_pages(None)
    if operation_name == "GetSinkPolicy":
        return {"Policy": json.dumps("policy"), "SinkArn": SINK_PAGE_ONE_ARN}
    if operation_name == "ListTagsForResource":
        return {"Tags": {}}
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_list_sinks_error(self, operation_name, kwarg):
    """ListSinks is denied, so no sink is collected."""
    if operation_name == "ListSinks":
        raise ClientError(
            {"Error": {"Code": "AccessDeniedException", "Message": "Denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    """Restricts the service to a single region so the collectors run once."""
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_OAM_Service:
    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_service(self):
        """The service class resolves to the oam botocore service name."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.service == "oam"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_client(self):
        """The regional clients are OAM clients."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        for regional_client in oam.regional_clients.values():
            assert (
                regional_client.__class__.__name__
                == "CloudWatchObservabilityAccessManager"
            )

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test__get_session__(self):
        """The service holds a boto3 session."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.session.__class__.__name__ == "Session"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_sinks_reads_every_page(self):
        """Every sink is collected, including those beyond the first ListSinks page."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].arn == SINK_PAGE_ONE_ARN
        assert oam.sinks[SINK_PAGE_ONE_ARN].id == "page-one"
        assert oam.sinks[SINK_PAGE_ONE_ARN].name == "sink-page-one"
        assert oam.sinks[SINK_PAGE_ONE_ARN].region == AWS_REGION_EU_WEST_1
        # The second sink only arrives if the paginator forwarded the NextToken.
        assert oam.sinks[SINK_PAGE_TWO_ARN].arn == SINK_PAGE_TWO_ARN
        assert oam.sinks[SINK_PAGE_TWO_ARN].id == "page-two"
        assert oam.sinks[SINK_PAGE_TWO_ARN].name == "sink-page-two"
        assert oam.sinks[SINK_PAGE_TWO_ARN].region == AWS_REGION_EU_WEST_1

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_sinks_audit_resources_filter(self):
        """Only sinks matching --resource-arn are collected."""
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        aws_provider._audit_resources = [SINK_PAGE_TWO_ARN]
        oam = OAM(aws_provider)
        assert SINK_PAGE_ONE_ARN not in oam.sinks
        assert oam.sinks[SINK_PAGE_TWO_ARN].name == "sink-page-two"

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_get_sink_policy_available(self):
        """A policy decoding to a populated object is stored and marked AVAILABLE."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy == ORGANIZATION_SINK_POLICY
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy_state == SinkPolicyState.AVAILABLE

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_get_sink_policy_absent(self):
        """ResourceNotFoundException is the determined ABSENT state, not UNKNOWN."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_TWO_ARN].policy is None
        assert oam.sinks[SINK_PAGE_TWO_ARN].policy_state == SinkPolicyState.ABSENT

    @patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_list_tags_for_resource(self):
        """Sink tags are collected onto the sink."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].tags == [{"environment": "production"}]

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_access_denied,
    )
    def test_get_sink_policy_unreadable(self):
        """A denied GetSinkPolicy leaves the policy UNKNOWN, not ABSENT."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy is None
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy_state == SinkPolicyState.UNKNOWN

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_unparseable_policy,
    )
    def test_get_sink_policy_unparseable(self):
        """A Policy member that is not JSON leaves the policy UNKNOWN."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy is None
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy_state == SinkPolicyState.UNKNOWN

    @patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_empty_policy
    )
    def test_get_sink_policy_empty_is_unknown_not_absent(self):
        """A successful GetSinkPolicy that returns nothing usable is not a determined ABSENT.

        AWS reports "no policy attached" with ResourceNotFoundException, which the collector
        maps to ABSENT deliberately. A 200 carrying an absent Policy member, an empty string
        or a document decoding to {} is a response we do not understand -- and ABSENT PASSes
        the sink as unlinkable by any account, which is the assertion we cannot make here.
        """
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy is None
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy_state == SinkPolicyState.UNKNOWN

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_scalar_policy,
    )
    def test_get_sink_policy_non_object_is_unknown_and_not_stored(self):
        """A policy decoding to a non-object is UNKNOWN and never reaches Sink.policy.

        Sink is a pydantic.v1 model without assignment validation, so storing the decoded
        document unconditionally would put a str where the dict annotation promises a
        policy. It would then read as truthy, be marked AVAILABLE, and abort the consuming
        check on its first .get() -- and because prowler catches that inside execute(), the
        findings for every other sink in the account would be discarded with it.
        """
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy is None
        assert oam.sinks[SINK_PAGE_ONE_ARN].policy_state == SinkPolicyState.UNKNOWN

        with patch(
            "prowler.providers.aws.services.oam.oam_sink_policy_restricted_to_organization.oam_sink_policy_restricted_to_organization.oam_client",
            new=oam,
        ):
            # Imported INSIDE the patch: the check module builds its client singleton at
            # import time, so importing it first constructs one against the real global
            # provider and reaches live AWS before the mock is in place.
            from prowler.providers.aws.services.oam.oam_sink_policy_restricted_to_organization.oam_sink_policy_restricted_to_organization import (
                oam_sink_policy_restricted_to_organization,
            )

            result = oam_sink_policy_restricted_to_organization().execute()

        assert [report.status for report in result] == ["MANUAL"]

    @patch(
        "botocore.client.BaseClient._make_api_call",
        new=mock_make_api_call_list_sinks_error,
    )
    def test_list_sinks_error(self):
        """A denied ListSinks yields no sinks rather than raising."""
        oam = OAM(set_mocked_aws_provider([AWS_REGION_EU_WEST_1]))
        assert oam.sinks == {}
