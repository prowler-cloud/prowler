from os import getcwd

import boto3
from mock import MagicMock
from moto import mock_s3

from prowler.config.config import csv_file_suffix, default_output_directory
from prowler.providers.aws.lib.s3.s3 import get_s3_object_path, send_to_s3_bucket

AWS_ACCOUNT_ID = "123456789012"
AWS_REGION = "us-east-1"


class TestS3:
    @mock_s3
    def test_send_to_s3_bucket(self):
        # Mock Audit Info
        audit_info = MagicMock()
        # Create mock session
        audit_info.audit_session = boto3.session.Session(region_name=AWS_REGION)
        audit_info.audited_account = AWS_ACCOUNT_ID
        # Create mock bucket
        bucket_name = "test_bucket"
        client = boto3.client("s3")
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
                Key=fixtures_dir + "/" + output_mode + "/" + filename + csv_file_suffix,
            )["ContentType"]
            == "binary/octet-stream"
        )

    @mock_s3
    def test_send_to_s3_bucket_compliance(self):
        # Mock Audit Info
        audit_info = MagicMock()
        # Create mock session
        audit_info.audit_session = boto3.session.Session(region_name=AWS_REGION)
        audit_info.audited_account = AWS_ACCOUNT_ID
        # Create mock bucket
        bucket_name = "test_bucket"
        client = boto3.client("s3")
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
        # Mock Audit Info
        audit_info = MagicMock()
        # Create mock session
        audit_info.audit_session = boto3.session.Session(region_name=AWS_REGION)
        audit_info.audited_account = AWS_ACCOUNT_ID
        # Create mock bucket
        bucket_name = "test_bucket"
        client = boto3.client("s3")
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
