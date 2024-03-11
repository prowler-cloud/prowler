import json

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


def scp_restrict_regions_with_deny():
    return '{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}}'


class Test_Organizations_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        assert organizations.service == "organizations"

    @mock_aws
    def test__describe_organization__(self):
        # Create Organization
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_organization()
        # Mock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        # Tests
        assert len(organizations.organizations) == 1
        assert organizations.organizations[0].arn == response["Organization"]["Arn"]
        assert organizations.organizations[0].id == response["Organization"]["Id"]
        assert (
            organizations.organizations[0].master_id
            == response["Organization"]["MasterAccountId"]
        )
        assert organizations.organizations[0].status == "ACTIVE"
        assert organizations.organizations[0].delegated_administrators == []

    @mock_aws
    def test__list_policies__(self):
        # Create Policy
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        conn.create_organization()
        response = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        # Mock
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        # Tests
        for policy in organizations.policies:
            if policy.arn == response["Policy"]["PolicySummary"]["Arn"]:
                assert policy.type == "SERVICE_CONTROL_POLICY"
                assert policy.aws_managed is False
                assert policy.content == json.loads(response["Policy"]["Content"])
                assert policy.targets == []
