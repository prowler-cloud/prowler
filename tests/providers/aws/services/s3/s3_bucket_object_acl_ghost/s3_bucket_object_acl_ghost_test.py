from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = "prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost"

ENABLED_CONFIG = {
    "s3_bucket_object_public_enabled": True,
    "s3_bucket_object_public_max_objects": 100,
    "s3_bucket_object_public_sample_size": 3,
}


class Test_s3_bucket_object_acl_ghost:
    @mock_aws
    def test_no_buckets(self):
        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_bucket_ownership_none_manual(self):
        """Ownership None is lookup failure, must be MANUAL, not PASS."""
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-ownership-none"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = None

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == bucket_name
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} ownership could not be determined, cannot evaluate ghost ACL risk. Check GetBucketOwnershipControls permission."
                )

    @mock_aws
    def test_bucket_without_enforced_pass_not_applicable(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-not-enforced"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = "BucketOwnerPreferred"

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == bucket_name
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].status_extended
                    == f"S3 Bucket {bucket_name} does not have BucketOwnerEnforced, ghost ACL check not applicable. Use s3_bucket_acl_prohibited and s3_bucket_object_public."
                )

    @mock_aws
    def test_bucket_enforced_no_sampling_manual(self):
        """When sampling None, should be MANUAL."""
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-no-sampling"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = "BucketOwnerEnforced"
                    b.object_sampling = None

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == bucket_name
                assert "Manual review" in result[0].status_extended or "could not be evaluated live" in result[0].status_extended

    @mock_aws
    def test_bucket_enforced_sampling_not_performed_manual(self):
        """Sampling performed=False also MANUAL."""
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-not-performed"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import BucketObjectSampling

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = "BucketOwnerEnforced"
                    b.object_sampling = BucketObjectSampling(
                        performed=False, is_empty=False, objects=[]
                    )

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert "could not be evaluated live" in result[0].status_extended or "Manual review" in result[0].status_extended

    @mock_aws
    def test_bucket_enforced_empty_pass(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-empty"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import BucketObjectSampling

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = "BucketOwnerEnforced"
                    b.object_sampling = BucketObjectSampling(
                        performed=True, is_empty=True, objects=[]
                    )

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].resource_id == bucket_name
                assert result[0].region == AWS_REGION_US_EAST_1
                assert result[0].status_extended == f"S3 Bucket {bucket_name} is empty, no ghost public ACLs."

    @mock_aws
    def test_bucket_enforced_non_empty_manual(self):
        """Live GetObjectAcl invalid under enforced, non-empty becomes MANUAL with inventory guidance."""
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-nonempty-manual"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_object(Bucket=bucket_name, Key="private-1.txt", Body=b"hello")

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import (
            ACL_Grantee,
            BucketObjectSampling,
            ObjectACL,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)

            for bucket in s3_service.buckets.values():
                if bucket.name == bucket_name:
                    bucket.ownership = "BucketOwnerEnforced"
                    private_grantee = ACL_Grantee(
                        type="CanonicalUser",
                        ID="owner-id",
                        display_name="owner",
                    )
                    private_grantee.URI = None
                    private_grantee.permission = "FULL_CONTROL"
                    sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[
                            ObjectACL(key="private-1.txt", grantees=[private_grantee]),
                        ],
                    )
                    bucket.object_sampling = sampling

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == bucket_name
                assert "BucketOwnerEnforced" in result[0].status_extended or "Enforced" in result[0].status_extended
                assert "S3 Inventory" in result[0].status_extended or "stored object ACLs" in result[0].status_extended or "Manual" in result[0].status_extended

    @mock_aws
    def test_bucket_enforced_ghost_public_becomes_manual(self):
        """Grant injection via sampling no longer FAIL, now MANUAL due to live sampling invalid."""
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-ghost-manual"
        ghost_key = "ghost-public.txt"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_object(Bucket=bucket_name, Key=ghost_key, Body=b"x")

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import (
            ACL_Grantee,
            BucketObjectSampling,
            ObjectACL,
        )

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)

            for bucket in s3_service.buckets.values():
                if bucket.name == bucket_name:
                    bucket.ownership = "BucketOwnerEnforced"
                    ghost_grantee = ACL_Grantee(type="Group")
                    ghost_grantee.URI = "http://acs.amazonaws.com/groups/global/AllUsers"
                    ghost_grantee.permission = "READ"
                    sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[
                            ObjectACL(key=ghost_key, grantees=[ghost_grantee]),
                        ],
                    )
                    bucket.object_sampling = sampling

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == bucket_name
                assert "blocked" in result[0].status_extended.lower() or "cannot be evaluated live" in result[0].status_extended.lower()

    @mock_aws
    def test_access_denied_manual_via_error_code(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-access-denied-ghost"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import BucketObjectSampling

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)

            for bucket in s3_service.buckets.values():
                if bucket.name == bucket_name:
                    bucket.ownership = "BucketOwnerEnforced"
                    bucket.object_sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[],
                        error_code="AccessDenied",
                        error_message="Access Denied when spot-checking objects in bucket",
                    )

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].resource_id == bucket_name

    @mock_aws
    def test_other_error_manual(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-other-error-ghost"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3
        from prowler.providers.aws.services.s3.s3_service import BucketObjectSampling

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)

            for bucket in s3_service.buckets.values():
                if bucket.name == bucket_name:
                    bucket.ownership = "BucketOwnerEnforced"
                    bucket.object_sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[],
                        error_code="InternalError",
                        error_message="InternalError when listing objects",
                    )

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
