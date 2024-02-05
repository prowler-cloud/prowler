from os import path
from pathlib import Path

import boto3
from mock import MagicMock
from moto import mock_aws

from prowler.config.config import csv_file_suffix
from prowler.providers.aws.lib.s3.s3 import get_s3_object_path, send_to_s3_bucket

AWS_ACCOUNT_ID = "123456789012"
AWS_REGION = "us-east-1"

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"

S3_BUCKET_NAME = "test_bucket"

OUTPUT_MODE_CSV = "csv"
OUTPUT_MODE_CIS_1_4_AWS = "cis_1.4_aws"


class TestS3:
    @mock_aws
    def test_send_to_s3_bucket(self):
        # Mock Audit Info
        audit_info = MagicMock()

        # Create mock session
        audit_info.audit_session = boto3.session.Session(region_name=AWS_REGION)
        audit_info.audited_account = AWS_ACCOUNT_ID

        # Create mock bucket
        client = audit_info.audit_session.client("s3")
        client.create_bucket(Bucket=S3_BUCKET_NAME)

        # Mocked CSV output file
        output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
        filename = f"prowler-output-{audit_info.audited_account}"

        # Send mock CSV file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            OUTPUT_MODE_CSV,
            S3_BUCKET_NAME,
            audit_info.audit_session,
        )

        bucket_directory = get_s3_object_path(output_directory)
        object_name = (
            f"{bucket_directory}/{OUTPUT_MODE_CSV}/{filename}{csv_file_suffix}"
        )

        assert (
            client.get_object(
                Bucket=S3_BUCKET_NAME,
                Key=object_name,
            )["ContentType"]
            == "binary/octet-stream"
        )

    @mock_aws
    def test_send_to_s3_bucket_compliance(self):
        # Mock Audit Info
        audit_info = MagicMock()

        # Create mock session
        audit_info.audit_session = boto3.session.Session(region_name=AWS_REGION)
        audit_info.audited_account = AWS_ACCOUNT_ID

        # Create mock bucket
        client = audit_info.audit_session.client("s3")
        client.create_bucket(Bucket=S3_BUCKET_NAME)

        # Mocked CSV output file
        output_directory = f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}"
        filename = f"prowler-output-{audit_info.audited_account}"

        # Send mock CSV file to mock S3 Bucket
        send_to_s3_bucket(
            filename,
            output_directory,
            OUTPUT_MODE_CIS_1_4_AWS,
            S3_BUCKET_NAME,
            audit_info.audit_session,
        )

        bucket_directory = get_s3_object_path(output_directory)
        object_name = f"{bucket_directory}/{OUTPUT_MODE_CIS_1_4_AWS}/{filename}_{OUTPUT_MODE_CIS_1_4_AWS}{csv_file_suffix}"

        assert (
            client.get_object(
                Bucket=S3_BUCKET_NAME,
                Key=object_name,
            )["ContentType"]
            == "binary/octet-stream"
        )

    def test_get_s3_object_path_with_prowler(self):
        output_directory = "/Users/admin/prowler/"
        assert (
            get_s3_object_path(output_directory)
            == output_directory.partition("prowler/")[-1]
        )

    def test_get_s3_object_path_without_prowler(self):
        output_directory = "/Users/admin/"
        assert get_s3_object_path(output_directory) == output_directory
