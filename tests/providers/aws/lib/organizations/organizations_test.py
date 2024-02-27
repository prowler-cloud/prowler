import json

import boto3
from moto import mock_aws

from prowler.providers.aws.lib.audit_info.models import AWS_Organizations_Info
from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
    parse_organizations_metadata,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
)


class Test_AWS_Organizations:
    @mock_aws
    def test_organizations(self):
        client = boto3.client("organizations", region_name=AWS_REGION_US_EAST_1)
        iam_client = boto3.client("iam", region_name=AWS_REGION_US_EAST_1)
        sts_client = boto3.client("sts", region_name=AWS_REGION_US_EAST_1)

        mockname = "mock-account"
        mockdomain = "moto-example.org"
        mockemail = "@".join([mockname, mockdomain])

        org_id = client.create_organization(FeatureSet="ALL")["Organization"]["Id"]
        account_id = client.create_account(AccountName=mockname, Email=mockemail)[
            "CreateAccountStatus"
        ]["AccountId"]

        client.tag_resource(
            ResourceId=account_id, Tags=[{"Key": "key", "Value": "value"}]
        )

        trust_policy_document = {
            "Version": "2012-10-17",
            "Statement": {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"},
                "Action": "sts:AssumeRole",
            },
        }
        iam_role_arn = iam_client.role_arn = iam_client.create_role(
            RoleName="test-role",
            AssumeRolePolicyDocument=json.dumps(trust_policy_document),
        )["Role"]["Arn"]
        session_name = "new-session"
        assumed_role = sts_client.assume_role(
            RoleArn=iam_role_arn, RoleSessionName=session_name
        )

        metadata, tags = get_organizations_metadata(account_id, assumed_role)
        org = parse_organizations_metadata(metadata, tags)

        assert org.account_details_email == mockemail
        assert org.account_details_name == mockname
        assert (
            org.account_details_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{org_id}/{account_id}"
        )
        assert org.account_details_org == org_id
        assert org.account_details_tags == "key:value,"

    def test_parse_organizations_metadata(self):
        tags = {"Tags": [{"Key": "test-key", "Value": "test-value"}]}
        name = "test-name"
        email = "test-email"
        organization_name = "test-org"
        arn = f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:organization/{organization_name}"
        metadata = {
            "Account": {
                "Name": name,
                "Email": email,
                "Arn": arn,
            }
        }
        org = parse_organizations_metadata(metadata, tags)

        assert isinstance(org, AWS_Organizations_Info)
        assert org.account_details_email == email
        assert org.account_details_name == name
        assert org.account_details_arn == arn
        assert org.account_details_org == organization_name
        assert org.account_details_tags == "test-key:test-value"
