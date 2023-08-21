from os import getcwd

from boto3 import session
from mock import patch
from moto import mock_s3

from prowler.config.config import csv_file_suffix, default_output_directory
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.s3.s3 import get_s3_object_path, send_to_s3_bucket
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_ID = "123456789012"
AWS_REGION = "us-east-1"


class TestS3:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_s3
    def test_send_to_s3_bucket(self):
        # Create mock audit_info
        audit_info = self.set_mocked_audit_info()
        with patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            audit_info,
        ):
            # Create mock bucket
            bucket_name = "test_bucket"
            client = audit_info.audit_session.client("s3", region_name=AWS_REGION)
            client.create_bucket(Bucket=bucket_name)

            # Create mock csv output file
            fixtures_dir = "tests/lib/outputs/fixtures"
            output_directory = getcwd() + "/" + fixtures_dir
            output_mode = "csv"
            filename = f"prowler-output-{audit_info.audited_account}"

            # Send mock csv file to mock S3 Bucket
            send_to_s3_bucket(
                filename,
                output_directory,
                output_mode,
                bucket_name,
                audit_info.audit_session,
            )

            # Check if the file has been sent by checking its content type
            assert (
                client.get_object(
                    Bucket=bucket_name,
                    Key=fixtures_dir
                    + "/"
                    + output_mode
                    + "/"
                    + filename
                    + csv_file_suffix,
                )["ContentType"]
                == "binary/octet-stream"
            )

    @mock_s3
    def test_send_to_s3_bucket_compliance(self):
        # Create mock audit_info
        audit_info = self.set_mocked_audit_info()
        with patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            audit_info,
        ):
            # Create mock bucket
            bucket_name = "test_bucket"
            client = audit_info.audit_session.client("s3", region_name=AWS_REGION)
            client.create_bucket(Bucket=bucket_name)

            # Create mock csv output file
            fixtures_dir = "tests/lib/outputs/fixtures"
            output_directory = getcwd() + "/" + fixtures_dir
            output_mode = "cis_1.4_aws"
            filename = f"prowler-output-{audit_info.audited_account}"

            # Send mock csv file to mock S3 Bucket
            send_to_s3_bucket(
                filename,
                output_directory,
                output_mode,
                bucket_name,
                audit_info.audit_session,
            )
            # Check if the file has been sent by checking its content type
            assert (
                client.get_object(
                    Bucket=bucket_name,
                    Key=fixtures_dir
                    + "/"
                    + output_mode
                    + "/"
                    + filename
                    + "_"
                    + output_mode
                    + csv_file_suffix,
                )["ContentType"]
                == "binary/octet-stream"
            )

    @mock_s3
    def test_send_to_s3_bucket_custom_directory(self):
        # Create mock audit_info
        audit_info = self.set_mocked_audit_info()
        with patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            audit_info,
        ):
            # Create mock bucket
            bucket_name = "test_bucket"
            client = audit_info.audit_session.client("s3", region_name=AWS_REGION)
            client.create_bucket(Bucket=bucket_name)

            # Create mock csv output file
            fixtures_dir = "fixtures"
            output_directory = f"tests/lib/outputs/{fixtures_dir}"
            output_mode = "csv"
            filename = f"prowler-output-{audit_info.audited_account}"

            # Send mock csv file to mock S3 Bucket
            send_to_s3_bucket(
                filename,
                output_directory,
                output_mode,
                bucket_name,
                audit_info.audit_session,
            )
            # Check if the file has been sent by checking its content type
            assert (
                client.get_object(
                    Bucket=bucket_name,
                    Key=output_directory
                    + "/"
                    + output_mode
                    + "/"
                    + filename
                    + csv_file_suffix,
                )["ContentType"]
                == "binary/octet-stream"
            )

    def test_get_s3_object_path_with_prowler(self):
        assert (
            get_s3_object_path(default_output_directory)
            == default_output_directory.partition("prowler/")[-1]
        )

    def test_get_s3_object_path_without_prowler(self):
        output_directory = "/Users/admin"
        assert get_s3_object_path(output_directory) == output_directory
