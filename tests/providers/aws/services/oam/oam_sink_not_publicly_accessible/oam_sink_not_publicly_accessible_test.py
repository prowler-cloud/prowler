import json
from unittest import mock

import botocore
import pytest
from botocore.exceptions import ClientError

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

SINK_NAME = "monitoring-sink"
SINK_ID = "a1b2c3d4-5678-90ab-cdef-example11111"
SINK_ARN = f"arn:aws:oam:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:sink/{SINK_ID}"
LINK_ACTIONS = ["oam:CreateLink", "oam:UpdateLink"]

make_api_call = botocore.client.BaseClient._make_api_call


def build_mock_make_api_call(policy):
    """One sink whose GetSinkPolicy returns `policy`, or no policy at all when None."""

    def mock_make_api_call(self, operation_name, kwarg):
        if operation_name == "ListSinks":
            return {"Items": [{"Arn": SINK_ARN, "Id": SINK_ID, "Name": SINK_NAME}]}
        if operation_name == "GetSinkPolicy":
            if policy is None:
                raise ClientError(
                    {"Error": {"Code": "ResourceNotFoundException", "Message": ""}},
                    operation_name,
                )
            return {"Policy": json.dumps(policy), "SinkArn": SINK_ARN}
        if operation_name == "ListTagsForResource":
            return {"Tags": {}}
        return make_api_call(self, operation_name, kwarg)

    return mock_make_api_call


def mock_make_api_call_no_sinks(self, operation_name, kwarg):
    if operation_name == "ListSinks":
        return {"Items": []}
    return make_api_call(self, operation_name, kwarg)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


def sink_policy(statement):
    return {"Version": "2012-10-17", "Statement": [statement]}


def execute_check():
    from prowler.providers.aws.services.oam.oam_service import OAM

    aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.oam.oam_sink_not_publicly_accessible.oam_sink_not_publicly_accessible.oam_client",
            new=OAM(aws_provider),
        ),
    ):
        from prowler.providers.aws.services.oam.oam_sink_not_publicly_accessible.oam_sink_not_publicly_accessible import (
            oam_sink_not_publicly_accessible,
        )

        return oam_sink_not_publicly_accessible().execute()


@mock.patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_oam_sink_not_publicly_accessible:
    @mock.patch(
        "botocore.client.BaseClient._make_api_call", new=mock_make_api_call_no_sinks
    )
    def test_no_sinks(self):
        assert execute_check() == []

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=build_mock_make_api_call(None),
    )
    def test_sink_without_policy(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"OAM sink {SINK_NAME} does not allow any AWS account to link to it."
        )
        assert result[0].resource_id == SINK_ID
        assert result[0].resource_arn == SINK_ARN
        assert result[0].region == AWS_REGION_EU_WEST_1
        assert result[0].resource_tags == [{}]

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=build_mock_make_api_call(
            sink_policy(
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                }
            )
        ),
    )
    def test_sink_policy_public(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            result[0].status_extended
            == f"OAM sink {SINK_NAME} allows any AWS account to link to it."
        )
        assert result[0].resource_id == SINK_ID
        assert result[0].resource_arn == SINK_ARN

    @pytest.mark.parametrize(
        "statement,expected_status",
        [
            # Documented organization scope
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalOrgID": "o-a1b2c3d4e5"},
                        "ForAllValues:StringEquals": {
                            "oam:ResourceTypes": ["AWS::CloudWatch::Metric"]
                        },
                    },
                },
                "PASS",
            ),
            # Organization path scope
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                    "Condition": {
                        "ForAnyValue:StringLike": {
                            "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/r-ab12/*"
                        }
                    },
                },
                "PASS",
            ),
            # Enumerated source accounts
            (
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": ["111122223333", "444455556666"]},
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                },
                "PASS",
            ),
            # Wildcard principal narrowed to specific accounts by condition
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                    "Condition": {
                        "StringEquals": {"aws:PrincipalAccount": ["111122223333"]}
                    },
                },
                "PASS",
            ),
            # Public, but only read-only actions that cannot link
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "oam:Get*",
                    "Resource": "*",
                },
                "PASS",
            ),
            # Every account root is as public as "*"
            (
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::*:root"},
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                },
                "FAIL",
            ),
            # Wildcard action reaching the link actions
            (
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "oam:*",
                    "Resource": "*",
                },
                "FAIL",
            ),
            # NotAction grants every OAM action, linking included
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "NotAction": "s3:*",
                    "Resource": "*",
                },
                "FAIL",
            ),
            # ForAllValues passes when the key is absent from the request
            (
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": LINK_ACTIONS,
                    "Resource": "*",
                    "Condition": {
                        "ForAllValues:StringLike": {
                            "aws:PrincipalOrgPaths": "o-a1b2c3d4e5/*"
                        }
                    },
                },
                "FAIL",
            ),
        ],
    )
    def test_sink_policy_statements(self, statement, expected_status):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=build_mock_make_api_call(sink_policy(statement)),
        ):
            result = execute_check()

        assert len(result) == 1
        assert result[0].status == expected_status

    @mock.patch(
        "botocore.client.BaseClient._make_api_call",
        new=build_mock_make_api_call(
            {
                "Version": "2012-10-17",
                "Statement": {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "oam:CreateLink",
                    "Resource": "*",
                },
            }
        ),
    )
    def test_sink_policy_single_statement_object(self):
        result = execute_check()

        assert len(result) == 1
        assert result[0].status == "FAIL"
