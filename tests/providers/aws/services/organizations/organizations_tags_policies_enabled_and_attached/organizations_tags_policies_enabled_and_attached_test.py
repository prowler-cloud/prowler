from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.audit_info import AWS_Audit_Info
from prowler.providers.aws.services.organizations.organizations_service import (
    Organization,
    Organizations,
    Policy,
)

AWS_REGION = "us-east-1"

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
            ),
            audited_account=None,
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=[AWS_REGION],
            organizations_metadata=None,
            audit_resources=None,
        )
        return audit_info

    def test_organization_no_active(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION
        organizations_client.organizations = [
            Organization(
                id="o-1234567890",
                arn="arn:aws:organizations::1234567890:organization/o-1234567890",
                status="NOT_ACTIVE",
                master_id="1234567890",
                policies=[],
                delegated_administrators=None,
            )
        ]

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_service.Organizations",
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
                == "AWS Organizations is not in-use for this AWS Account"
            )
            assert result[0].resource_id == "AWS Organization"
            assert (
                result[0].resource_arn
                == ""
            )
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

        with mock.patch(
            "prowler.providers.aws.services.organizations.organizations_service.Organizations",
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
                == "TAG Policies exist at the organization o-1234567890 level but not attached"
            )
            assert result[0].resource_id == "o-1234567890"
            assert (
                result[0].resource_arn
                == "arn:aws:organizations::1234567890:organization/o-1234567890"
            )
            assert result[0].region == AWS_REGION

    # def test_organization_with_tag_policies_attached(self):
    #     organizations_client = mock.MagicMock
    #     organizations_client.region = AWS_REGION
    #     organizations_client.organizations = [
    #         Organization(
    #             id="o-1234567890",
    #             arn="arn:aws:organizations::1234567890:organization/o-1234567890",
    #             status="ACTIVE",
    #             master_id="1234567890",
    #             policies=[
    #                 Policy(
    #                     id="p-1234567890",
    #                     arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
    #                     type="TAG_POLICY",
    #                     aws_managed=False,
    #                     content={"tags": {"Owner": {}}},
    #                     targets=["1234567890"],
    #                 )
    #             ],
    #             delegated_administrators=None,
    #         )
    #     ]

    #     with mock.patch(
    #         "prowler.providers.aws.services.organizations.organizations_service.Organizations",
    #         new=organizations_client,
    #     ):
    #         # Test Check
    #         from prowler.providers.aws.services.organizations.organizations_tags_policies_enabled_and_attached.organizations_tags_policies_enabled_and_attached import (
    #             organizations_tags_policies_enabled_and_attached,
    #         )

    #         check = organizations_tags_policies_enabled_and_attached()
    #         result = check.execute()

    #         assert len(result) == 1
    #         assert result[0].status == "PASS"
    #         assert (
    #             result[0].status_extended
    #             == "TAG Policies exist at the organization o-1234567890 level and are attached"
    #         )
    #         assert result[0].resource_id == "o-1234567890"
    #         assert (
    #             result[0].resource_arn
    #             == "arn:aws:organizations::1234567890:organization/o-1234567890"
    #         )
    #         assert result[0].region == AWS_REGION
