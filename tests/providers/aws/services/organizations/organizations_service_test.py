import json

from boto3 import client, session
from moto import mock_organizations
from moto.core import DEFAULT_ACCOUNT_ID

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organizations,
)

AWS_REGION = "eu-west-1"


class Test_Organizations_Service:

    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=DEFAULT_ACCOUNT_ID,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    @mock_organizations
    def test_service(self):
        audit_info = self.set_mocked_audit_info()
        organizations = Organizations(audit_info)
        assert organizations.service == "organizations"

    @mock_organizations
    def test__describe_organization__(self):
        # Create Organization
        conn = client("organizations", region_name=AWS_REGION)
        response = conn.create_organization()
        # Mock
        audit_info = self.set_mocked_audit_info()
        organizations = Organizations(audit_info)
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

    @mock_organizations
    def test__list_policies__(self):
        # Create Policy
        conn = client("organizations", region_name=AWS_REGION)
        conn.create_organization()
        response = conn.create_policy(
            Content='{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"s3:*"}}',
            Description="Enables admins of attached accounts to delegate all S3 permissions",
            Name="AllowAllS3Actions",
            Type="SERVICE_CONTROL_POLICY",
        )
        # Mock
        audit_info = self.set_mocked_audit_info()
        organizations = Organizations(audit_info)
        # Tests
        assert len(organizations.policies) == 2
        for policy in organizations.policies:
            if policy.arn == response["Policy"]["PolicySummary"]["Arn"]:
                assert policy.type == "SERVICE_CONTROL_POLICY"
                assert policy.aws_managed is False
                assert policy.content == json.loads(response["Policy"]["Content"])
                assert policy.targets == []
