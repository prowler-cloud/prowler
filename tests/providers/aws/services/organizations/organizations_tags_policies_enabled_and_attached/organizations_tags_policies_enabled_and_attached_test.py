from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organization,
    Policy,
)
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_ID = "123456789012"
AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_ID}:root"
# Moto: NotImplementedError: The TAG_POLICY policy type has not been implemented
# Needs to Mock manually


class Test_organizations_tags_policies_enabled_and_attached:
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
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=AWS_ACCOUNT_ARN,
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
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    def test_organization_no_organization(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION
        organizations_client.organizations = [
            Organization(
                arn=AWS_ACCOUNT_ARN,
                id="AWS Organization",
                status="NOT_AVAILABLE",
                master_id="",
            )
        ]

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached import (
                    organizations_tags_policies_enabled_and_attached,
                )

                check = organizations_tags_policies_enabled_and_attached()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organizations is not in-use for this AWS Account."
                )
                assert result[0].resource_id == "AWS Organization"
                assert result[0].resource_arn == AWS_ACCOUNT_ARN
                assert result[0].region == AWS_REGION

    def test_organization_with_tag_policies_not_attached(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION
        organizations_client.organizations = [
            Organization(
                id="o-1234567890",
                arn="arn:aws:organizations::1234567890:organization/o-1234567890",
                status="ACTIVE",
                master_id="1234567890",
                policies=[
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="TAG_POLICY",
                        aws_managed=False,
                        content={"tags": {"Owner": {}}},
                        targets=[],
                    )
                ],
                delegated_administrators=None,
            )
        ]

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached import (
                    organizations_tags_policies_enabled_and_attached,
                )

                check = organizations_tags_policies_enabled_and_attached()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has tag policies enabled but not attached."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION

    def test_organization_with_tag_policies_attached(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION
        organizations_client.organizations = [
            Organization(
                id="o-1234567890",
                arn="arn:aws:organizations::1234567890:organization/o-1234567890",
                status="ACTIVE",
                master_id="1234567890",
                policies=[
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="TAG_POLICY",
                        aws_managed=False,
                        content={"tags": {"Owner": {}}},
                        targets=["1234567890"],
                    )
                ],
                delegated_administrators=None,
            )
        ]

        audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached import (
                    organizations_tags_policies_enabled_and_attached,
                )

                check = organizations_tags_policies_enabled_and_attached()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has tag policies enabled and attached to an AWS account."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION
