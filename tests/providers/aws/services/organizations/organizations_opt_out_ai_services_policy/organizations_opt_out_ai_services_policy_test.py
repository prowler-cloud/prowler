from unittest import mock

from prowler.providers.aws.services.organizations.organizations_service import (
    Organization,
    Policy,
)
from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_organizations_tags_policies_enabled_and_attached:
    def test_organization_no_organization(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.organization = Organization(
            arn="arn:aws:organizations:eu-west-1:0123456789012:unknown",
            id="AWS Organization",
            status="NOT_AVAILABLE",
            master_id="",
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organizations is not in-use for this AWS Account."
                )
                assert result[0].resource_id == "AWS Organization"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations:eu-west-1:0123456789012:unknown"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_organization_with_AI_optout_no_policies(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.organization = Organization(
            id="o-1234567890",
            arn="arn:aws:organizations::1234567890:organization/o-1234567890",
            status="ACTIVE",
            master_id="1234567890",
            policies={"AISERVICES_OPT_OUT_POLICY": []},
            delegated_administrators=None,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has no opt-out policy for AI services."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_organization_with_AI_optout_policy_complete(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.get_unknown_arn = (
            lambda x: f"arn:aws:organizations:{x}:0123456789012:unknown"
        )
        organizations_client.organization = Organization(
            id="o-1234567890",
            arn="arn:aws:organizations::1234567890:organization/o-1234567890",
            status="ACTIVE",
            master_id="1234567890",
            policies={
                "AISERVICES_OPT_OUT_POLICY": [
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="AISERVICES_OPT_OUT_POLICY",
                        aws_managed=False,
                        content={
                            "services": {
                                "default": {
                                    "opt_out_policy": {
                                        "@@operators_allowed_for_child_policies": [
                                            "@@none"
                                        ],
                                        "@@assign": "optOut",
                                    }
                                }
                            }
                        },
                        targets=[],
                    )
                ]
            },
            delegated_administrators=None,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with (
                mock.patch(
                    "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                    new=organizations_client,
                ),
                mock.patch(
                    "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client.get_unknown_arn",
                    return_value="arn:aws:organizations:eu-west-1:0123456789012:unknown",
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has opted out of all AI services and also disallows child-accounts to overwrite this policy."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_organization_with_AI_optout_policy_no_content(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.organization = Organization(
            id="o-1234567890",
            arn="arn:aws:organizations::1234567890:organization/o-1234567890",
            status="ACTIVE",
            master_id="1234567890",
            policies={
                "AISERVICES_OPT_OUT_POLICY": [
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="AISERVICES_OPT_OUT_POLICY",
                        aws_managed=False,
                        content={},
                        targets=[],
                    )
                ]
            },
            delegated_administrators=None,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has not opted out of all AI services and it does not disallow child-accounts to overwrite the policy."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_organization_with_AI_optout_policy_no_disallow(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.organization = Organization(
            id="o-1234567890",
            arn="arn:aws:organizations::1234567890:organization/o-1234567890",
            status="ACTIVE",
            master_id="1234567890",
            policies={
                "AISERVICES_OPT_OUT_POLICY": [
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="AISERVICES_OPT_OUT_POLICY",
                        aws_managed=False,
                        content={
                            "services": {
                                "default": {"opt_out_policy": {"@@assign": "optOut"}}
                            }
                        },
                        targets=[],
                    )
                ]
            },
            delegated_administrators=None,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has opted out of all AI services but it does not disallow child-accounts to overwrite the policy."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_organization_with_AI_optout_policy_no_opt_out(self):
        organizations_client = mock.MagicMock
        organizations_client.region = AWS_REGION_EU_WEST_1
        organizations_client.audited_partition = "aws"
        organizations_client.audited_account = "0123456789012"
        organizations_client.organization = Organization(
            id="o-1234567890",
            arn="arn:aws:organizations::1234567890:organization/o-1234567890",
            status="ACTIVE",
            master_id="1234567890",
            policies={
                "AISERVICES_OPT_OUT_POLICY": [
                    Policy(
                        id="p-1234567890",
                        arn="arn:aws:organizations::1234567890:policy/o-1234567890/p-1234567890",
                        type="AISERVICES_OPT_OUT_POLICY",
                        aws_managed=False,
                        content={
                            "services": {
                                "default": {
                                    "opt_out_policy": {
                                        "@@operators_allowed_for_child_policies": [
                                            "@@none"
                                        ]
                                    }
                                }
                            }
                        },
                        targets=[],
                    )
                ]
            },
            delegated_administrators=None,
        )

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy.organizations_client",
                new=organizations_client,
            ):
                # Test Check
                from prowler.providers.aws.services.organizations.organizations_opt_out_ai_services_policy.organizations_opt_out_ai_services_policy import (
                    organizations_opt_out_ai_services_policy,
                )

                check = organizations_opt_out_ai_services_policy()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == "AWS Organization o-1234567890 has not opted out of all AI services."
                )
                assert result[0].resource_id == "o-1234567890"
                assert (
                    result[0].resource_arn
                    == "arn:aws:organizations::1234567890:organization/o-1234567890"
                )
                assert result[0].region == AWS_REGION_EU_WEST_1
