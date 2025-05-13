import os
import zipfile
from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError
from tasks.jobs.export import (
    _compress_output_files,
    _generate_output_directory,
    _upload_to_s3,
    get_s3_client,
)


@pytest.mark.django_db
class TestOutputs:
    def test_compress_output_files_creates_zip(self, tmp_path_factory):
        base_tmp = tmp_path_factory.mktemp("compress_output")
        output_dir = base_tmp / "output"
        output_dir.mkdir()
        file_path = output_dir / "result.csv"
        file_path.write_text("data")

        zip_path = _compress_output_files(str(output_dir))

        assert zip_path.endswith(".zip")
        assert os.path.exists(zip_path)
        with zipfile.ZipFile(zip_path, "r") as zipf:
            assert "output/result.csv" in zipf.namelist()

    @patch("tasks.jobs.export.boto3.client")
    @patch("tasks.jobs.export.settings")
    def test_get_s3_client_success(self, mock_settings, mock_boto_client):
        mock_settings.DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID = "test"
        mock_settings.DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY = "test"
        mock_settings.DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN = "token"
        mock_settings.DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION = "eu-west-1"

        client_mock = MagicMock()
        mock_boto_client.return_value = client_mock

        client = get_s3_client()
        assert client is not None
        client_mock.list_buckets.assert_called()

    @patch("tasks.jobs.export.boto3.client")
    @patch("tasks.jobs.export.settings")
    def test_get_s3_client_fallback(self, mock_settings, mock_boto_client):
        mock_boto_client.side_effect = [
            ClientError({"Error": {"Code": "403"}}, "ListBuckets"),
            MagicMock(),
        ]
        client = get_s3_client()
        assert client is not None

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_success(self, mock_base, mock_get_client, tmp_path_factory):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"

        base_tmp = tmp_path_factory.mktemp("upload_success")
        zip_path = base_tmp / "outputs.zip"
        zip_path.write_bytes(b"dummy")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "report.csv").write_text("ok")

        client_mock = MagicMock()
        mock_get_client.return_value = client_mock

        result = _upload_to_s3("tenant-id", str(zip_path), "scan-id")

        expected_uri = "s3://test-bucket/tenant-id/scan-id/outputs.zip"
        assert result == expected_uri
        assert client_mock.upload_file.call_count == 2

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_missing_bucket(self, mock_base, mock_get_client):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = ""
        result = _upload_to_s3("tenant", "/tmp/fake.zip", "scan")
        assert result is None

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_skips_non_files(
        self, mock_base, mock_get_client, tmp_path_factory
    ):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"
        base_tmp = tmp_path_factory.mktemp("upload_skips_non_files")

        zip_path = base_tmp / "results.zip"
        zip_path.write_bytes(b"zip")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "subdir").mkdir()

        client_mock = MagicMock()
        mock_get_client.return_value = client_mock

        result = _upload_to_s3("tenant", str(zip_path), "scan")

        expected_uri = "s3://test-bucket/tenant/scan/results.zip"
        assert result == expected_uri
        client_mock.upload_file.assert_called_once()

    @patch(
        "tasks.jobs.export.get_s3_client",
        side_effect=ClientError({"Error": {}}, "Upload"),
    )
    @patch("tasks.jobs.export.base")
    @patch("tasks.jobs.export.logger.error")
    def test_upload_to_s3_failure_logs_error(
        self, mock_logger, mock_base, mock_get_client, tmp_path_factory
    ):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "bucket"

        base_tmp = tmp_path_factory.mktemp("upload_failure_logs")
        zip_path = base_tmp / "zipfile.zip"
        zip_path.write_bytes(b"zip")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "report.csv").write_text("csv")

        _upload_to_s3("tenant", str(zip_path), "scan")
        mock_logger.assert_called()

    def test_generate_output_directory_creates_paths(self, tmp_path_factory):
        from prowler.config.config import output_file_timestamp

        base_tmp = tmp_path_factory.mktemp("generate_output")
        base_dir = str(base_tmp)
        tenant_id = "t1"
        scan_id = "s1"
        provider = "aws"

        path, compliance = _generate_output_directory(
            base_dir, provider, tenant_id, scan_id
        )

        assert os.path.isdir(os.path.dirname(path))
        assert os.path.isdir(os.path.dirname(compliance))

        assert path.endswith(f"{provider}-{output_file_timestamp}")
        assert compliance.endswith(f"{provider}-{output_file_timestamp}")
