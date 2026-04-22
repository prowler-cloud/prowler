from unittest import mock

from boto3 import client
from botocore.exceptions import ClientError
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK_MODULE = (
    "prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public"
)


class Test_s3_bucket_object_public:
    @mock_aws
    def test_check_disabled_by_default_returns_no_findings(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        s3_client_us_east_1.create_bucket(Bucket="bucket-disabled")

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert result == []

    @mock_aws
    def test_bucket_empty_passes(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-empty"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            s3_service.audit_config = {
                "s3_bucket_object_public_enabled": True,
                "s3_bucket_object_public_max_objects": 100,
                "s3_bucket_object_public_sample_size": 3,
            }
            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert result[0].status_extended == (
                    f"S3 Bucket {bucket_name} is empty."
                )
                assert result[0].resource_id == bucket_name
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_bucket_with_only_private_objects_passes(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-private-objects"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)
        s3_client_us_east_1.put_object(
            Bucket=bucket_name, Key="private-1.txt", Body=b"x"
        )
        s3_client_us_east_1.put_object(
            Bucket=bucket_name, Key="private-2.txt", Body=b"x"
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            s3_service.audit_config = {
                "s3_bucket_object_public_enabled": True,
                "s3_bucket_object_public_max_objects": 100,
                "s3_bucket_object_public_sample_size": 3,
            }
            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert "No public objects detected in spot-check sample of" in (
                    result[0].status_extended
                )
                assert bucket_name in result[0].status_extended
                assert (
                    "For complete assurance, ensure ACLs are disabled via "
                    "Object Ownership settings."
                ) in result[0].status_extended

    @mock_aws
    def test_bucket_with_public_object_fails(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-public-object"
        public_key = "public.txt"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)
        s3_client_us_east_1.put_object(Bucket=bucket_name, Key=public_key, Body=b"x")
        s3_client_us_east_1.put_object_acl(
            Bucket=bucket_name, Key=public_key, ACL="public-read"
        )

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            s3_service.audit_config = {
                "s3_bucket_object_public_enabled": True,
                "s3_bucket_object_public_max_objects": 100,
                "s3_bucket_object_public_sample_size": 3,
            }
            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert public_key in result[0].status_extended
                assert (
                    f"S3 Bucket {bucket_name} has public objects detected in "
                    "spot-check sample of"
                ) in result[0].status_extended

    @mock_aws
    def test_access_denied_on_list_objects_reports_manual(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-access-denied"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            s3_service.audit_config = {
                "s3_bucket_object_public_enabled": True,
                "s3_bucket_object_public_max_objects": 100,
                "s3_bucket_object_public_sample_size": 3,
            }

            regional_client = mock.MagicMock()
            regional_client.list_objects_v2.side_effect = ClientError(
                {"Error": {"Code": "AccessDenied", "Message": "denied"}},
                "ListObjectsV2",
            )
            s3_service.regional_clients[AWS_REGION_US_EAST_1] = regional_client

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert result[0].status_extended == (
                    f"Access Denied when spot-checking objects in bucket "
                    f"{bucket_name}."
                )

    @mock_aws
    def test_other_client_error_reports_manual(self):
        s3_client_us_east_1 = client("s3", region_name=AWS_REGION_US_EAST_1)
        bucket_name = "bucket-other-error"
        s3_client_us_east_1.create_bucket(Bucket=bucket_name)

        from prowler.providers.aws.services.s3.s3_service import S3

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            s3_service = S3(aws_provider)
            s3_service.audit_config = {
                "s3_bucket_object_public_enabled": True,
                "s3_bucket_object_public_max_objects": 100,
                "s3_bucket_object_public_sample_size": 3,
            }

            regional_client = mock.MagicMock()
            regional_client.list_objects_v2.side_effect = ClientError(
                {"Error": {"Code": "InternalError", "Message": "boom"}},
                "ListObjectsV2",
            )
            s3_service.regional_clients[AWS_REGION_US_EAST_1] = regional_client

            with mock.patch(f"{CHECK_MODULE}.s3_client", new=s3_service):
                from prowler.providers.aws.services.s3.s3_bucket_object_public.s3_bucket_object_public import (
                    s3_bucket_object_public,
                )

                check = s3_bucket_object_public()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "MANUAL"
                assert (
                    f"Could not spot-check objects in bucket {bucket_name}"
                ) in result[0].status_extended
