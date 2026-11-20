from json import dumps, loads
from unittest import mock

import botocore
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider

mock_make_api_call = botocore.client.BaseClient._make_api_call

vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:123456789012:vaults/test-vault"

public_statement = {
    "Sid": "Public",
    "Effect": "Allow",
    "Principal": {"AWS": "*"},
    "Action": "glacier:*",
    "Resource": vault_arn,
}

account_statement = {
    "Sid": "AccountRead",
    "Effect": "Allow",
    "Principal": {"AWS": "arn:aws:iam::123456789012:root"},
    "Action": "glacier:InitiateJob",
    "Resource": vault_arn,
}

deny_statement = {
    "Sid": "DenyDelete",
    "Effect": "Deny",
    "Principal": "*",
    "Action": "glacier:DeleteArchive",
    "Resource": vault_arn,
}

# Vault access policy stored by the mocked Glacier API calls
vault_policy = {}


def mock_make_api_call_vault_policy(self, operation_name, kwarg):
    if operation_name == "GetVaultAccessPolicy":
        return {"policy": {"Policy": dumps(vault_policy["policy"])}}
    if operation_name == "SetVaultAccessPolicy":
        vault_policy["policy"] = loads(kwarg["policy"]["Policy"])
        return {}
    if operation_name == "DeleteVaultAccessPolicy":
        vault_policy.clear()
        return {
            "ResponseMetadata": {
                "HTTPStatusCode": 204,
                "RequestId": "test-request-id",
            }
        }
    return mock_make_api_call(self, operation_name, kwarg)


def mock_make_api_call_public_vault_error(self, operation_name, kwarg):
    if operation_name == "GetVaultAccessPolicy":
        raise botocore.exceptions.ClientError(
            {
                "Error": {
                    "Code": "ResourceNotFoundException",
                    "Message": "Vault not found",
                }
            },
            operation_name,
        )
    return mock_make_api_call(self, operation_name, kwarg)


class Test_glacier_vaults_policy_public_access_fixer:
    @mock_aws
    def test_glacier_vault_public(self):
        vault_policy.clear()
        vault_policy["policy"] = {
            "Version": "2012-10-17",
            "Statement": [public_statement],
        }
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_vault_policy,
        ):
            from prowler.providers.aws.services.glacier.glacier_service import Glacier

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer.glacier_client",
                    new=Glacier(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer import (
                    fixer,
                )

                assert fixer(resource_id="test-vault", region=AWS_REGION_EU_WEST_1)
                # Only a public statement was present, so the policy is deleted
                assert vault_policy == {}

    @mock_aws
    def test_glacier_vault_public_keeps_non_public_statements(self):
        vault_policy.clear()
        vault_policy["policy"] = {
            "Version": "2012-10-17",
            "Statement": [public_statement, account_statement, deny_statement],
        }
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_vault_policy,
        ):
            from prowler.providers.aws.services.glacier.glacier_service import Glacier

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer.glacier_client",
                    new=Glacier(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer import (
                    fixer,
                )

                assert fixer(resource_id="test-vault", region=AWS_REGION_EU_WEST_1)
                assert vault_policy["policy"]["Statement"] == [
                    account_statement,
                    deny_statement,
                ]

    @mock_aws
    def test_glacier_vault_public_error(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_public_vault_error,
        ):
            from prowler.providers.aws.services.glacier.glacier_service import Glacier

            aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer.glacier_client",
                    new=Glacier(aws_provider),
                ),
            ):
                from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access_fixer import (
                    fixer,
                )

                assert not fixer(resource_id="test-vault", region=AWS_REGION_EU_WEST_1)
