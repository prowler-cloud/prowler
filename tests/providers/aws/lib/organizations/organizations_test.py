import json

import boto3
from moto import mock_iam, mock_organizations, mock_sts

from prowler.providers.aws.lib.organizations.organizations import (
    get_organizations_metadata,
)

AWS_ACCOUNT_NUMBER = "123456789012"


class Test_AWS_Organizations:
    @mock_organizations
    @mock_sts
    @mock_iam
    def test_organizations(self):
        client = boto3.client("organizations", region_name="us-east-1")
        iam_client = boto3.client("iam", region_name="us-east-1")
        sts_client = boto3.client("sts", region_name="us-east-1")

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

        org = get_organizations_metadata(account_id, assumed_role)

        assert org.account_details_email == mockemail
        assert org.account_details_name == mockname
        assert (
            org.account_details_arn
            == f"arn:aws:organizations::{AWS_ACCOUNT_NUMBER}:account/{org_id}/{account_id}"
        )
        assert org.account_details_org == org_id
        assert org.account_details_tags == "key:value,"
