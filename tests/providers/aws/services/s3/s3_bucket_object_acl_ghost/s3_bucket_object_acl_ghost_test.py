from unittest import mock

from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = "prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost"

ENABLED_CONFIG = {
    "s3_bucket_object_public_enabled": True,
    "s3_bucket_object_public_max_objects": 100,
    "s3_bucket_object_public_sample_size": 3,
}

PUBLIC_ALL_USERS_URI = "http://acs.amazonaws.com/groups/global/AllUsers"
PUBLIC_AUTH_USERS_URI = "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"


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
            # Ensure bucket.ownership is None/empty to simulate non-enforced
            # (S3 service would normally set None when OwnershipControlsNotFound)
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
                assert "does not have BucketOwnerEnforced" in result[0].status_extended
                assert "ghost ACL check not applicable" in result[0].status_extended
                assert (
                    result[0].resource_arn
                    == f"arn:{aws_provider.identity.partition}:s3:::{bucket_name}"
                )

    @mock_aws
    def test_bucket_enforced_empty_pass(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-empty"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=ENABLED_CONFIG
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            # Force ownership to BucketOwnerEnforced in case moto doesn't persist
            for b in s3_service.buckets.values():
                if b.name == bucket_name:
                    b.ownership = "BucketOwnerEnforced"

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
                # When empty, service sets is_empty=True -> message contains empty
                assert (
                    "is empty" in result[0].status_extended
                    or "no ghost public ACLs" in result[0].status_extended.lower()
                    or "no object ACL sampling available" in result[0].status_extended
                )

    @mock_aws
    def test_bucket_enforced_no_ghost_pass_clean(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-no-ghost"
        s3_client_us_east_1.create_bucket(
            Bucket=bucket_name, ObjectOwnership="BucketOwnerEnforced"
        )
        s3_client_us_east_1.put_object(
            Bucket=bucket_name, Key="private-1.txt", Body=b"hello"
        )
        s3_client_us_east_1.put_object(
            Bucket=bucket_name, Key="private-2.txt", Body=b"world"
        )

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

            # Manually inject sampling with no ghost public ACLs
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
                            ObjectACL(key="private-2.txt", grantees=[private_grantee]),
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
                assert result[0].status == "PASS"
                assert result[0].resource_id == bucket_name
                assert "no ghost public ACLs" in result[0].status_extended.lower() or "ACL drift is clean" in result[0].status_extended
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_enforced_ghost_public_allusers_fail(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-ghost-drift"
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
                    ghost_grantee = ACL_Grantee(
                        type="Group",
                    )
                    ghost_grantee.URI = PUBLIC_ALL_USERS_URI
                    ghost_grantee.permission = "READ"
                    ghost_grantee.display_name = None
                    ghost_grantee.ID = None
                    private_grantee = ACL_Grantee(
                        type="CanonicalUser",
                        ID="owner",
                    )
                    private_grantee.display_name = "owner"
                    sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[
                            ObjectACL(key=ghost_key, grantees=[ghost_grantee]),
                            ObjectACL(key="private.txt", grantees=[private_grantee]),
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
                assert result[0].status == "FAIL"
                assert result[0].resource_id == bucket_name
                assert ghost_key in result[0].status_extended
                assert "ghost public ACL" in result[0].status_extended.lower()
                assert "BucketOwnerEnforced" in result[0].status_extended
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_enforced_ghost_authenticated_users_fail(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-enforced-ghost-auth"
        ghost_key = "ghost-auth.txt"
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
                    ghost_grantee.URI = PUBLIC_AUTH_USERS_URI
                    ghost_grantee.permission = "READ"
                    sampling = BucketObjectSampling(
                        performed=True,
                        is_empty=False,
                        objects=[ObjectACL(key=ghost_key, grantees=[ghost_grantee])],
                    )
                    bucket.object_sampling = sampling

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert ghost_key in result[0].status_extended

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
                    # Simulate AccessDenied scenario that S3 service would capture
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
                assert bucket_name in result[0].status_extended

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

            # Simulate generic error via mocked regional client like s3_bucket_object_public test does
            regional_client = mock.MagicMock()
            regional_client.region = AWS_REGION_US_EAST_1
            regional_client.list_objects_v2.side_effect = ClientError(
                {"Error": {"Code": "InternalError", "Message": "boom"}},
                "ListObjectsV2",
            )
            s3_service.regional_clients[AWS_REGION_US_EAST_1] = regional_client
            for bucket in s3_service.buckets.values():
                if bucket.name == bucket_name:
                    bucket.ownership = "BucketOwnerEnforced"
                    bucket.object_sampling = None
                    s3_service._get_public_objects(bucket)

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_acl_ghost.s3_bucket_object_acl_ghost import (
                    s3_bucket_object_acl_ghost,
                )

                check = s3_bucket_object_acl_ghost()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert bucket_name in result[0].status_extended
