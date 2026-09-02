from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import Registry, Repository
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)


class Test_ecr_repository_encrypted_with_cmk:
    def test_no_registries(self):
        """Test when there are no registries."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_registry_no_repositories(self):
        """Test when registry has no repositories."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[],
            rules=[],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 0

    def test_repository_aes256_encryption(self):
        """Test repository with AES256 encryption."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="AES256",
                    kms_key=None,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} does not have KMS encryption configured with a customer-managed key."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn

    def test_repository_kms_aws_managed(self):
        """Test repository with AWS managed KMS encryption."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = [
            mock.MagicMock(
                arn=kms_arn,
                manager="AWS",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} does not have KMS encryption configured with a customer-managed key."
            )

    def test_repository_kms_customer_managed(self):
        """Test repository with Customer managed KMS encryption."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = [
            mock.MagicMock(
                arn=kms_arn,
                manager="CUSTOMER",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} has KMS encryption configured with a customer-managed key."
            )

    def test_repository_kms_key_not_in_inventory(self):
        """Test repository with KMS encryption but key not found in KMS inventory."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert kms_arn in result[0].status_extended

    def test_repository_kms_key_manager_unknown(self):
        """Test repository whose KMS key was listed but could not be described."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        # DescribeKey failed for this key, so its manager was never populated
        kms_client = mock.MagicMock()
        kms_client.keys = [
            mock.MagicMock(
                arn=kms_arn,
                manager=None,
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert kms_arn in result[0].status_extended

    def test_repository_kms_dsse_customer_managed(self):
        """Test repository with dual-layer KMS encryption and a customer managed key."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS_DSSE",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = [
            mock.MagicMock(
                arn=kms_arn,
                manager="CUSTOMER",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} has KMS encryption configured with a customer-managed key."
            )

    def test_repository_kms_dsse_aws_managed(self):
        """Test repository with dual-layer KMS encryption and an AWS managed key."""
        kms_arn = f"arn:aws:kms:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:key/1234abcd-12ab-34cd-56ef-1234567890ab"
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS_DSSE",
                    kms_key=kms_arn,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = [
            mock.MagicMock(
                arn=kms_arn,
                manager="AWS",
            )
        ]

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} does not have KMS encryption configured with a customer-managed key."
            )

    def test_repository_kms_without_key(self):
        """Test repository reporting KMS encryption without a key configured."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            rules=[],
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    immutability="MUTABLE",
                    encryption_type="KMS",
                    kms_key=None,
                    policy=None,
                    images_details=None,
                    lifecycle_policy=None,
                )
            ],
        )

        kms_client = mock.MagicMock()
        kms_client.keys = []

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk.kms_client",
                new=kms_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_encrypted_with_cmk.ecr_repository_encrypted_with_cmk import (
                ecr_repository_encrypted_with_cmk,
            )

            check = ecr_repository_encrypted_with_cmk()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Repository {repository_name} does not have KMS encryption configured with a customer-managed key."
            )
