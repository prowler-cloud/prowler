from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

mock_make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call_public_vault(self, operation_name, kwarg):
    if operation_name == "SetVaultAccessPolicy":
        return {
            "VaultAccessPolicy": {
                "Policy": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": {"AWS": "arn:aws:iam::106908755756:root"},
                            "Action": "glacier:InitiateJob",
                            "Resource": "arn:aws:glacier:eu-west-1:106908755756:vaults/test-vault",
                        }
                    ],
                }
            }
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_public_vault_error(self, operation_name, kwarg):
    if operation_name == "SetVaultAccessPolicy":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "VaultNotFound",
                    "Message": "VaultNotFound",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_glacier_vaults_policy_public_access_fixer:
    @mock_aws
    def test_glacier_vault_public(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_vault,
        ):
            from prowler.providers.aws.services.glacier.glacier_service import Glacier

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer.glacier_client",
                new=Glacier(aws_provider),
            ):
                from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer import (
                    fixer,
                )

                assert fixer(resource_id="test-vault", region=AWS_REGION_EU_WEST_1)

    @mock_aws
    def test_glacier_vault_public_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_vault_error,
        ):
            from prowler.providers.aws.services.glacier.glacier_service import Glacier

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ), mock.patch(
                "prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer.glacier_client",
                new=Glacier(aws_provider),
            ):
                from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer import (
                    fixer,
                )

                assert not fixer(resource_id="test-vault", region=AWS_REGION_EU_WEST_1)
