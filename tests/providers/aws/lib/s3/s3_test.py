from os import getcwd

from boto3 import client, session
from moto import mock_s3

from prowler.config.config import csv_file_suffix, default_output_directory
from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.lib.s3.s3 import get_s3_object_path, send_to_s3_bucket
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_ID = "123456789012"


class TestS3:
    def set_mocked_audit_info(self):
        return AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_ID,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_ID}:root",
            audited_identity_arn="test-arn",
            audited_user_id="test",
            audited_partition="aws",
            profile="default",
            profile_region="eu-west-1",
            credentials=None,
            assumed_role_info=None,
            audited_regions=["eu-west-2", "eu-west-1"],
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

    @mock_s3
    def test_send_to_s3_bucket(self):
        # Mocked Audit Info
        input_audit_info = self.set_mocked_audit_info()
        # Create mock bucket
        bucket_name = "test_bucket"
        s3_client = client("s3")
        s3_client.create_bucket(Bucket=bucket_name)
        # Create mock csv output file
        fixtures_dir = "tests/lib/outputs/fixtures"
        output_directory = getcwd() + "/" + fixtures_dir
        output_mode = "csv"
        filename = f"prowler-output-{input_audit_info.audited_account}"
        # Send mock csv file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            output_mode,
            bucket_name,
            input_audit_info.audit_session,
        )
        # Check if the file has been sent by checking its content type
        assert (
            s3_client.get_object(
                Bucket=bucket_name,
                Key=fixtures_dir + "/" + output_mode + "/" + filename + csv_file_suffix,
            )["ContentType"]
            == "binary/octet-stream"
        )

    @mock_s3
    def test_send_to_s3_bucket_compliance(self):
        # Mocked Audit Info
        input_audit_info = self.set_mocked_audit_info()
        # Create mock bucket
        bucket_name = "test_bucket"
        s3_client = client("s3")
        s3_client.create_bucket(Bucket=bucket_name)
        # Create mock csv output file
        fixtures_dir = "tests/lib/outputs/fixtures"
        output_directory = getcwd() + "/" + fixtures_dir
        output_mode = "cis_1.4_aws"
        filename = f"prowler-output-{input_audit_info.audited_account}"
        # Send mock csv file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            output_mode,
            bucket_name,
            input_audit_info.audit_session,
        )
        # Check if the file has been sent by checking its content type
        assert (
            s3_client.get_object(
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
        # Mocked Audit Info
        input_audit_info = self.set_mocked_audit_info()
        # Create mock bucket
        bucket_name = "test_bucket"
        s3_client = client("s3")
        s3_client.create_bucket(Bucket=bucket_name)
        # Create mock csv output file
        fixtures_dir = "fixtures"
        output_directory = f"tests/lib/outputs/{fixtures_dir}"
        output_mode = "csv"
        filename = f"prowler-output-{input_audit_info.audited_account}"
        # Send mock csv file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            output_mode,
            bucket_name,
            input_audit_info.audit_session,
        )
        # Check if the file has been sent by checking its content type
        assert (
            s3_client.get_object(
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
        assert get_s3_object_path(default_output_directory) == "output"

    def test_get_s3_object_path_without_prowler(self):
        output_directory = "/Users/admin"
        assert get_s3_object_path(output_directory) == output_directory
