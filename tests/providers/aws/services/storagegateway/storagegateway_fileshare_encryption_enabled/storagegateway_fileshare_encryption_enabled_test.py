from unittest import mock

from prowler.providers.aws.services.storagegateway.storagegateway_service import (
    FileShare,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

test_gateway = "sgw-12A3456B"
test_gateway_arn = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{test_gateway}"
test_kms_key = f"arn:aws:kms:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:key/b72aaa2a-2222-99tt-12345690qwe"
test_share_nfs = "share-nfs2wwe"
test_share_arn_nfs = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_nfs}"
test_share_smb = "share-smb2wwe"
test_share_arn_smb = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_smb}"


class Test_storagegateway_fileshare_encryption_enabled:
    def test_no_storagegateway_fileshare(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.fileshares = []
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import (
                storagegateway_fileshare_encryption_enabled,
            )

            check = storagegateway_fileshare_encryption_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_nfs_fileshare_kms_encryption(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.fileshares = []
        storagegateway_client.fileshares.append(
            FileShare(
                id=test_share_nfs,
                arn=test_share_arn_nfs,
                gateway_arn=test_gateway_arn,
                region=AWS_REGION_US_EAST_1,
                fs_type="NFS",
                status="AVAILABLE",
                kms=True,
                kms_key=test_kms_key,
                tags=[
                    {"Key": "test", "Value": "test"},
                ],
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import (
                storagegateway_fileshare_encryption_enabled,
            )

            check = storagegateway_fileshare_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"StorageGateway File Share {test_share_nfs} is using KMS CMK."
            )
            assert result[0].resource_id == f"{test_share_nfs}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_nfs}"
            )
            assert result[0].resource_tags == [
                {"Key": "test", "Value": "test"},
            ]

    def test_nfs_fileshare_no_kms_encryption(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.fileshares = []
        storagegateway_client.fileshares.append(
            FileShare(
                id=test_share_nfs,
                arn=test_share_arn_nfs,
                gateway_arn=test_gateway_arn,
                region=AWS_REGION_US_EAST_1,
                fs_type="NFS",
                status="AVAILABLE",
                kms=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import (
                storagegateway_fileshare_encryption_enabled,
            )

            check = storagegateway_fileshare_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"StorageGateway File Share {test_share_nfs} is not using KMS CMK."
            )
            assert result[0].resource_id == f"{test_share_nfs}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_nfs}"
            )
            assert result[0].resource_tags == []

    def test_smb_fileshare_kms_encryption(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.fileshares = []
        storagegateway_client.fileshares.append(
            FileShare(
                id=test_share_smb,
                arn=test_share_arn_smb,
                gateway_arn=test_gateway_arn,
                region=AWS_REGION_US_EAST_1,
                fs_type="SMB",
                status="AVAILABLE",
                kms=True,
                kms_key=test_kms_key,
                tags=[
                    {"Key": "test", "Value": "test"},
                ],
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import (
                storagegateway_fileshare_encryption_enabled,
            )

            check = storagegateway_fileshare_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"StorageGateway File Share {test_share_smb} is using KMS CMK."
            )
            assert result[0].resource_id == f"{test_share_smb}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_smb}"
            )
            assert result[0].resource_tags == [
                {"Key": "test", "Value": "test"},
            ]

    def test_smb_fileshare_no_kms_encryption(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.fileshares = []
        storagegateway_client.fileshares.append(
            FileShare(
                id=test_share_smb,
                arn=test_share_arn_smb,
                gateway_arn=test_gateway_arn,
                region=AWS_REGION_US_EAST_1,
                fs_type="SMB",
                status="AVAILABLE",
                kms=False,
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fileshare_encryption_enabled.storagegateway_fileshare_encryption_enabled import (
                storagegateway_fileshare_encryption_enabled,
            )

            check = storagegateway_fileshare_encryption_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"StorageGateway File Share {test_share_smb} is not using KMS CMK."
            )
            assert result[0].resource_id == f"{test_share_smb}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:share/{test_share_smb}"
            )
            assert result[0].resource_tags == []
