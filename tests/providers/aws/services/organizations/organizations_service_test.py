import json
from unittest.mock import patch

import botocore
from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

orig_make_api_call = botocore.client.BaseClient._make_api_call


def scp_restrict_regions_with_deny():
    return '{"Version":"2012-10-17","Statement":{"Effect":"Deny","NotAction":"s3:*","Resource":"*","Condition":{"StringNotEquals":{"aws:RequestedRegion":["eu-central-1"]}}}}'


def make_mock_delegated_services_access_denied():
    def _mock(self, operation_name, api_params):
        if operation_name == "ListDelegatedServicesForAccount":
            raise botocore.exceptions.ClientError(
                {
                    "Error": {
                        "Code": "AccessDeniedException",
                        "Message": "User is not authorized to perform: organizations:ListDelegatedServicesForAccount",
                    }
                },
                operation_name,
            )
        return orig_make_api_call(self, operation_name, api_params)

    return _mock


def make_mock_delegated_services_unexpected_exception():
    def _mock(self, operation_name, api_params):
        if operation_name == "ListDelegatedServicesForAccount":
            raise RuntimeError("simulated transient error")
        return orig_make_api_call(self, operation_name, api_params)

    return _mock


class Test_Organizations_Service:
    @mock_aws
    def test_service(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        organizations = Organizations(aws_provider)
        assert organizations.service == "organizations"

    @mock_aws
    def test_describe_organization(self):
        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1],
        )
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.describe_organization()
        organizations = Organizations(aws_provider)
        assert organizations.organization.arn == response["Organization"]["Arn"]
        assert organizations.organization.id == response["Organization"]["Id"]
        assert (
            organizations.organization.master_id
            == response["Organization"]["MasterAccountId"]
        )
        assert organizations.organization.status == "ACTIVE"
        assert organizations.organization.delegated_administrators == []

    @mock_aws
    def test_list_policies(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        organizations = Organizations(aws_provider)
        for policy in organizations.policies:
            if policy.arn == response["Policy"]["PolicySummary"]["Arn"]:
                assert policy.type == "SERVICE_CONTROL_POLICY"
                assert policy.aws_managed is False
                assert policy.content == json.loads(response["Policy"]["Content"])
                assert policy.targets == []

    @mock_aws
    def test_describe_policy(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        response = conn.create_policy(
            Content=scp_restrict_regions_with_deny(),
            Description="Test",
            Name="Test",
            Type="SERVICE_CONTROL_POLICY",
        )
        organizations = Organizations(aws_provider)
        policy = organizations._describe_policy(
            response["Policy"]["PolicySummary"]["Id"]
        )
        assert policy == json.loads(response["Policy"]["Content"])

    @mock_aws
    def test_list_delegated_services_for_account_access_denied(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        account = conn.create_account(Email="test@test.com", AccountName="test")
        account_id = account["CreateAccountStatus"]["AccountId"]
        conn.register_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_delegated_services_access_denied(),
        ):
            organizations = Organizations(aws_provider)

        assert len(organizations.delegated_administrators) == 1
        assert organizations.delegated_administrators[0].id == account_id
        assert organizations.delegated_administrators[0].delegated_services is None

    @mock_aws
    def test_list_delegated_services_for_account_unexpected_exception(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])
        conn = client("organizations", region_name=AWS_REGION_EU_WEST_1)
        account = conn.create_account(Email="test@test.com", AccountName="test")
        account_id = account["CreateAccountStatus"]["AccountId"]
        conn.register_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal="config-multiaccountsetup.amazonaws.com",
        )

        with patch(
            "botocore.client.BaseClient._make_api_call",
            new=make_mock_delegated_services_unexpected_exception(),
        ):
            organizations = Organizations(aws_provider)

        assert len(organizations.delegated_administrators) == 1
        assert organizations.delegated_administrators[0].id == account_id
        assert organizations.delegated_administrators[0].delegated_services is None
