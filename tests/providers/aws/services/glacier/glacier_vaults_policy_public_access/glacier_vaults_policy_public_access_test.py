from unittest import mock

from prowler.providers.aws.services.glacier.glacier_service import Vault
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class Test_glacier_vaults_policy_public_access:
    def test_no_vaults(self):
        glacier_client = mock.MagicMock
        glacier_client.vaults = {}
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 0

    def test_vault_no_policy(self):
        glacier_client = mock.MagicMock
        vault_name = "test-vault"
        vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        glacier_client.vaults = {
            vault_name: Vault(
                name=vault_name,
                arn=vault_arn,
                access_policy={},
                region=AWS_REGION_EU_WEST_1,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == vault_name
            assert result[0].resource_arn == vault_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Vault {vault_name} does not have a policy."
            )

    def test_vault_policy_pricipal_aws_list_asterisk(self):
        glacier_client = mock.MagicMock
        vault_name = "test-vault"
        vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        glacier_client.vaults = {
            vault_name: Vault(
                name=vault_name,
                arn=vault_arn,
                access_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "cross-account-upload",
                            "Principal": {"AWS": ["*", AWS_ACCOUNT_NUMBER]},
                            "Effect": "Allow",
                            "Action": [
                                "glacier:UploadArchive",
                                "glacier:InitiateMultipartUpload",
                                "glacier:AbortMultipartUpload",
                                "glacier:CompleteMultipartUpload",
                            ],
                            "Resource": [
                                f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
                            ],
                        }
                    ],
                },
                region=AWS_REGION_EU_WEST_1,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == vault_name
            assert result[0].resource_arn == vault_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Vault {vault_name} has policy which allows access to everyone."
            )

    def test_vault_policy_pricipal_asterisk(self):
        glacier_client = mock.MagicMock
        vault_name = "test-vault"
        vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        glacier_client.vaults = {
            vault_name: Vault(
                name=vault_name,
                arn=vault_arn,
                access_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "cross-account-upload",
                            "Principal": {"AWS": ["*"]},
                            "Effect": "Allow",
                            "Action": [
                                "glacier:UploadArchive",
                                "glacier:InitiateMultipartUpload",
                                "glacier:AbortMultipartUpload",
                                "glacier:CompleteMultipartUpload",
                            ],
                            "Resource": [
                                f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
                            ],
                        }
                    ],
                },
                region=AWS_REGION_EU_WEST_1,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == vault_name
            assert result[0].resource_arn == vault_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Vault {vault_name} has policy which allows access to everyone."
            )

    def test_vault_policy_pricipal_canonical_user_asterisk(self):
        glacier_client = mock.MagicMock
        vault_name = "test-vault"
        vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        glacier_client.vaults = {
            vault_name: Vault(
                name=vault_name,
                arn=vault_arn,
                access_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "cross-account-upload",
                            "Principal": {"CanonicalUser": ["*"]},
                            "Effect": "Allow",
                            "Action": [
                                "glacier:UploadArchive",
                                "glacier:InitiateMultipartUpload",
                                "glacier:AbortMultipartUpload",
                                "glacier:CompleteMultipartUpload",
                            ],
                            "Resource": [
                                f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
                            ],
                        }
                    ],
                },
                region=AWS_REGION_EU_WEST_1,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == vault_name
            assert result[0].resource_arn == vault_arn
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Vault {vault_name} has policy which allows access to everyone."
            )

    def test_vault_policy_private(self):
        glacier_client = mock.MagicMock
        vault_name = "test-vault"
        vault_arn = f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
        glacier_client.vaults = {
            vault_name: Vault(
                name=vault_name,
                arn=vault_arn,
                access_policy={
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "cross-account-upload",
                            "Principal": {
                                "CanonicalUser": [
                                    f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
                                ]
                            },
                            "Effect": "Allow",
                            "Action": [
                                "glacier:UploadArchive",
                                "glacier:InitiateMultipartUpload",
                                "glacier:AbortMultipartUpload",
                                "glacier:CompleteMultipartUpload",
                            ],
                            "Resource": [
                                f"arn:aws:glacier:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:vaults/examplevault"
                            ],
                        }
                    ],
                },
                region=AWS_REGION_EU_WEST_1,
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.glacier.glacier_service.Glacier",
            new=glacier_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glacier.glacier_vaults_policy_public_access.glacier_vaults_policy_public_access import (
                glacier_vaults_policy_public_access,
            )

            check = glacier_vaults_policy_public_access()
            result = check.execute()

            assert len(result) == 1
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_id == vault_name
            assert result[0].resource_arn == vault_arn
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Vault {vault_name} has policy which does not allow access to everyone."
            )
