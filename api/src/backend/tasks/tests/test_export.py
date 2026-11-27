import gzip
import os
import uuid
import zipfile
import zlib
from datetime import datetime
from pathlib import Path
from unittest.mock import MagicMock, call, patch
from urllib.parse import parse_qs, urlparse

import boto3
import pytest
from botocore.exceptions import ClientError
from django.test import override_settings
from tasks.jobs.export import (
    _compress_output_files,
    _generate_compliance_output_directory,
    _generate_output_directory,
    _remove_archived_files,
    _upload_to_s3,
    get_s3_client,
    get_s3_presign_client,
)


@pytest.mark.django_db
class TestOutputs:
    def test_compress_output_files_creates_zip(self, tmpdir):
        base_tmp = Path(str(tmpdir.mkdir("compress_output")))
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
    @override_settings(
        DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID="access-key",
        DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY="secret-key",
        DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN="",
        DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION="",
    )
    def test_get_s3_client_without_a_region_uses_a_default(self, mock_boto_client):
        """botocore rejects an empty region up front, and the download views do not catch it."""
        get_s3_client()

        assert mock_boto_client.call_args.kwargs["region_name"] == "us-east-1"

    @patch("tasks.jobs.export.boto3.client")
    @override_settings(DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL="http://minio:9000")
    def test_get_s3_client_passes_the_endpoint_when_set(self, mock_boto_client):
        get_s3_client()

        assert mock_boto_client.call_args.kwargs["endpoint_url"] == "http://minio:9000"

    @patch("tasks.jobs.export.boto3.client")
    @override_settings(DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL="")
    def test_get_s3_client_endpoint_empty_by_default(self, mock_boto_client):
        """Empty keeps today's behavior: no endpoint override, real S3 is used."""
        get_s3_client()

        assert mock_boto_client.call_args.kwargs["endpoint_url"] is None

    @patch("tasks.jobs.export.boto3.client")
    @override_settings(DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL="http://minio:9000")
    def test_get_s3_client_does_not_fall_back_when_endpoint_set(self, mock_boto_client):
        """A configured endpoint means the explicit client failed talking to it. The fallback
        goes to the default provider chain (e.g. an EC2 instance role) against real AWS, so it
        must not be used: the original error propagates instead."""
        error = ClientError({"Error": {"Code": "403"}}, "ListBuckets")
        mock_boto_client.side_effect = error

        with pytest.raises(ClientError):
            get_s3_client()

        mock_boto_client.assert_called_once()

    @patch("tasks.jobs.export.boto3.client")
    @patch("tasks.jobs.export.settings")
    def test_get_s3_client_fallback(self, mock_settings, mock_boto_client):
        mock_settings.DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL = ""
        mock_boto_client.side_effect = [
            ClientError({"Error": {"Code": "403"}}, "ListBuckets"),
            MagicMock(),
        ]
        client = get_s3_client()
        assert client is not None
        assert mock_boto_client.call_args_list[1] == call("s3")

    def test_remove_archived_files_keeps_only_archive_and_unarchived(self, tmpdir):
        scan_dir = Path(str(tmpdir.mkdir("scan")))
        output = scan_dir / "prowler-output-aws-20260101000000"
        (scan_dir / "prowler-output-aws-20260101000000.csv").write_text("finding")
        compliance_dir = scan_dir / "compliance"
        compliance_dir.mkdir()
        (
            compliance_dir / "prowler-output-aws-20260101000000_cis_1.4_aws.csv"
        ).write_text("requirement")

        zip_path = _compress_output_files(str(output))

        pdf_dir = scan_dir / "threatscore"
        pdf_dir.mkdir()
        (pdf_dir / "report.pdf").write_bytes(b"pdf")

        _remove_archived_files(zip_path)

        assert sorted(p.name for p in scan_dir.iterdir()) == [
            "prowler-output-aws-20260101000000.zip",
            "threatscore",
        ]
        assert (pdf_dir / "report.pdf").exists()
        with zipfile.ZipFile(zip_path) as zipf:
            assert sorted(zipf.namelist()) == [
                "compliance/prowler-output-aws-20260101000000_cis_1.4_aws.csv",
                "prowler-output-aws-20260101000000.csv",
            ]

    def test_remove_archived_files_keeps_files_changed_after_archiving(self, tmpdir):
        scan_dir = Path(str(tmpdir.mkdir("scan")))
        loose = scan_dir / "out.csv"
        loose.write_text("row-1\n")
        zip_path = _compress_output_files(str(scan_dir / "out"))
        loose.write_text("row-1\nrow-2\n")

        _remove_archived_files(zip_path)

        assert loose.read_text() == "row-1\nrow-2\n"

    def test_remove_archived_files_keeps_everything_when_a_member_is_corrupt(
        self, tmpdir
    ):
        scan_dir = Path(str(tmpdir.mkdir("scan")))
        loose = scan_dir / "out.csv"
        loose.write_text("finding;" * 500)
        zip_path = Path(_compress_output_files(str(scan_dir / "out")))
        raw = bytearray(zip_path.read_bytes())
        with zipfile.ZipFile(zip_path) as zipf:
            data_offset = zipf.infolist()[0].header_offset + 30 + len("out.csv")
        raw[data_offset + 2] ^= 0xFF
        zip_path.write_bytes(bytes(raw))

        with pytest.raises((zipfile.BadZipFile, zlib.error)):
            _remove_archived_files(str(zip_path))

        assert loose.exists()

    def test_remove_archived_files_ignores_members_outside_the_scan_dir(self, tmpdir):
        base_dir = Path(str(tmpdir.mkdir("base")))
        outside = base_dir / "outside.csv"
        outside.write_text("keep")
        scan_dir = base_dir / "scan"
        scan_dir.mkdir()
        zip_path = scan_dir / "out.zip"
        with zipfile.ZipFile(zip_path, "w") as zipf:
            zipf.writestr("../outside.csv", "keep")

        _remove_archived_files(str(zip_path))

        assert outside.read_text() == "keep"

    def test_remove_archived_files_keeps_unrelated_empty_directories(self, tmpdir):
        scan_dir = Path(str(tmpdir.mkdir("scan")))
        (scan_dir / "out.csv").write_text("finding")
        zip_path = _compress_output_files(str(scan_dir / "out"))
        (scan_dir / "threatscore").mkdir()

        _remove_archived_files(zip_path)

        assert (scan_dir / "threatscore").is_dir()

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_gzip_encode_removes_temp_file_when_upload_fails(
        self, mock_base, mock_get_client, tmpdir
    ):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"
        artifact = Path(str(tmpdir.mkdir("gzip_fail"))) / "report.csv"
        artifact.write_text("row")
        mock_get_client.return_value.upload_file.side_effect = ClientError(
            {"Error": {"Code": "500"}}, "PutObject"
        )

        result = _upload_to_s3(
            "tenant-id", "scan-id", str(artifact), "compliance/report.csv", True
        )

        assert result is None
        assert [p.name for p in artifact.parent.iterdir()] == ["report.csv"]

    @patch("tasks.jobs.export.gzip.open", side_effect=OSError(28, "No space left"))
    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_gzip_encode_falls_back_to_plain_upload_without_disk_space(
        self, mock_base, mock_get_client, _mock_gzip_open, tmpdir
    ):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"
        artifact = Path(str(tmpdir.mkdir("gzip_enospc"))) / "report.csv"
        artifact.write_text("row")

        result = _upload_to_s3(
            "tenant-id", "scan-id", str(artifact), "compliance/report.csv", True
        )

        assert result == "s3://test-bucket/tenant-id/scan-id/compliance/report.csv"
        mock_get_client.return_value.upload_file.assert_called_once_with(
            Filename=str(artifact),
            Bucket="test-bucket",
            Key="tenant-id/scan-id/compliance/report.csv",
        )

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_gzip_encode(self, mock_base, mock_get_client, tmpdir):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"
        artifact = Path(str(tmpdir.mkdir("gzip"))) / "report_dora.ocsf.json"
        artifact.write_text("[" + "{}," * 1000 + "{}]")

        uploaded = {}

        def capture(**kwargs):
            gzip_file = Path(kwargs["Filename"])
            uploaded["key"] = kwargs["Key"]
            uploaded["extra"] = kwargs["ExtraArgs"]
            uploaded["body"] = gzip.decompress(gzip_file.read_bytes())
            uploaded["size"] = gzip_file.stat().st_size

        client_mock = MagicMock()
        client_mock.upload_file.side_effect = capture
        mock_get_client.return_value = client_mock

        result = _upload_to_s3(
            "tenant-id",
            "scan-id",
            str(artifact),
            "compliance/report_dora.ocsf.json",
            gzip_encode=True,
        )

        assert result == (
            "s3://test-bucket/tenant-id/scan-id/compliance/report_dora.ocsf.json"
        )
        assert uploaded["key"] == "tenant-id/scan-id/compliance/report_dora.ocsf.json"
        assert uploaded["extra"] == {"ContentEncoding": "gzip"}
        assert uploaded["body"] == artifact.read_bytes()
        assert uploaded["size"] < artifact.stat().st_size
        assert not Path(f"{artifact}.gz").exists()

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_success(self, mock_base, mock_get_client, tmpdir):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"

        base_tmp = Path(str(tmpdir.mkdir("upload_success")))
        zip_path = base_tmp / "outputs.zip"
        zip_path.write_bytes(b"dummy")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "report.csv").write_text("ok")

        client_mock = MagicMock()
        mock_get_client.return_value = client_mock

        result = _upload_to_s3(
            "tenant-id",
            "scan-id",
            str(zip_path),
            "outputs.zip",
        )

        expected_uri = "s3://test-bucket/tenant-id/scan-id/outputs.zip"
        assert result == expected_uri
        client_mock.upload_file.assert_called_once_with(
            Filename=str(zip_path),
            Bucket="test-bucket",
            Key="tenant-id/scan-id/outputs.zip",
        )

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_missing_bucket(self, mock_base, mock_get_client):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = ""
        result = _upload_to_s3("tenant", "scan", "/tmp/fake.zip", "fake.zip")
        assert result is None

    @patch("tasks.jobs.export.get_s3_client")
    @patch("tasks.jobs.export.base")
    def test_upload_to_s3_skips_non_files(self, mock_base, mock_get_client, tmpdir):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "test-bucket"
        base_tmp = Path(str(tmpdir.mkdir("upload_skips_non_files")))

        zip_path = base_tmp / "results.zip"
        zip_path.write_bytes(b"zip")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "subdir").mkdir()

        client_mock = MagicMock()
        mock_get_client.return_value = client_mock

        result = _upload_to_s3(
            "tenant",
            "scan",
            str(compliance_dir / "subdir"),
            "compliance/subdir",
        )

        assert result is None
        client_mock.upload_file.assert_not_called()

    @patch(
        "tasks.jobs.export.get_s3_client",
        side_effect=ClientError({"Error": {}}, "Upload"),
    )
    @patch("tasks.jobs.export.base")
    @patch("tasks.jobs.export.logger.error")
    def test_upload_to_s3_failure_logs_error(
        self, mock_logger, mock_base, mock_get_client, tmpdir
    ):
        mock_base.DJANGO_OUTPUT_S3_AWS_OUTPUT_BUCKET = "bucket"

        base_tmp = Path(str(tmpdir.mkdir("upload_failure_logs")))
        zip_path = base_tmp / "zipfile.zip"
        zip_path.write_bytes(b"zip")

        compliance_dir = base_tmp / "compliance"
        compliance_dir.mkdir()
        (compliance_dir / "report.csv").write_text("csv")

        _upload_to_s3(
            "tenant",
            "scan",
            str(zip_path),
            "zipfile.zip",
        )
        mock_logger.assert_called()

    @patch("tasks.jobs.export.set_output_timestamp")
    @patch("tasks.jobs.export.rls_transaction")
    @patch("tasks.jobs.export.Scan")
    def test_generate_output_directory_creates_paths(
        self, mock_scan, mock_rls_transaction, mock_set_timestamp, tmpdir
    ):
        # Mock the scan object with a started_at timestamp
        mock_scan_instance = MagicMock()
        mock_scan_instance.started_at = datetime(2023, 6, 15, 10, 30, 45)
        mock_scan.objects.get.return_value = mock_scan_instance

        # Mock rls_transaction as a context manager
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock(return_value=False)

        base_tmp = Path(str(tmpdir.mkdir("generate_output")))
        base_dir = str(base_tmp)
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        provider = "aws"
        expected_timestamp = "20230615103045"

        # Test _generate_output_directory (returns standard and compliance paths)
        path, compliance = _generate_output_directory(
            base_dir, provider, tenant_id, scan_id
        )

        assert os.path.isdir(os.path.dirname(path))
        assert os.path.isdir(os.path.dirname(compliance))
        assert path.endswith(f"{provider}-{expected_timestamp}")
        assert compliance.endswith(f"{provider}-{expected_timestamp}")
        assert "/compliance/" in compliance

        # Test _generate_compliance_output_directory with "threatscore"
        threatscore = _generate_compliance_output_directory(
            base_dir, provider, tenant_id, scan_id, compliance_framework="threatscore"
        )

        assert os.path.isdir(os.path.dirname(threatscore))
        assert threatscore.endswith(f"{provider}-{expected_timestamp}")
        assert "/threatscore/" in threatscore

        # Test _generate_compliance_output_directory with "ens"
        ens = _generate_compliance_output_directory(
            base_dir, provider, tenant_id, scan_id, compliance_framework="ens"
        )

        assert os.path.isdir(os.path.dirname(ens))
        assert ens.endswith(f"{provider}-{expected_timestamp}")
        assert "/ens/" in ens

    @patch("tasks.jobs.export.set_output_timestamp")
    @patch("tasks.jobs.export.rls_transaction")
    @patch("tasks.jobs.export.Scan")
    def test_generate_output_directory_invalid_character(
        self, mock_scan, mock_rls_transaction, mock_set_timestamp, tmpdir
    ):
        # Mock the scan object with a started_at timestamp
        mock_scan_instance = MagicMock()
        mock_scan_instance.started_at = datetime(2023, 6, 15, 10, 30, 45)
        mock_scan.objects.get.return_value = mock_scan_instance

        # Mock rls_transaction as a context manager
        mock_rls_transaction.return_value.__enter__ = MagicMock()
        mock_rls_transaction.return_value.__exit__ = MagicMock(return_value=False)

        base_tmp = Path(str(tmpdir.mkdir("generate_output")))
        base_dir = str(base_tmp)
        tenant_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        provider = "aws/test@check"
        expected_timestamp = "20230615103045"

        # Test provider name sanitization with _generate_output_directory
        path, compliance = _generate_output_directory(
            base_dir, provider, tenant_id, scan_id
        )

        assert os.path.isdir(os.path.dirname(path))
        assert os.path.isdir(os.path.dirname(compliance))
        assert path.endswith(f"aws-test-check-{expected_timestamp}")
        assert compliance.endswith(f"aws-test-check-{expected_timestamp}")

        # Test provider name sanitization with _generate_compliance_output_directory
        threatscore = _generate_compliance_output_directory(
            base_dir, provider, tenant_id, scan_id, compliance_framework="threatscore"
        )
        ens = _generate_compliance_output_directory(
            base_dir, provider, tenant_id, scan_id, compliance_framework="ens"
        )

        assert os.path.isdir(os.path.dirname(threatscore))
        assert os.path.isdir(os.path.dirname(ens))
        assert threatscore.endswith(f"aws-test-check-{expected_timestamp}")
        assert ens.endswith(f"aws-test-check-{expected_timestamp}")


PRESIGN_SETTINGS = {
    "DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID": "access-key",
    "DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY": "secret-key",
    "DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN": "",
    "DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION": "eu-west-1",
}


def _presign(client):
    return client.generate_presigned_url(
        "get_object",
        Params={"Bucket": "output-bucket", "Key": "tenant/scan/report.zip"},
        ExpiresIn=300,
    )


class TestS3PresignClient:
    @override_settings(
        **{**PRESIGN_SETTINGS, "DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION": ""},
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="",
    )
    def test_no_public_endpoint_and_no_region_returns_none(self):
        # Without a region, SigV4 would have to guess one and break other regions.
        assert get_s3_presign_client() is None

    @override_settings(**PRESIGN_SETTINGS, DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="")
    def test_region_without_public_endpoint_signs_sigv4_on_the_regional_host(self):
        # SSE-KMS objects reject the SigV2 URLs boto3 presigns by default, and the
        # global host redirects for new buckets, which breaks a SigV4 signature.
        url = urlparse(_presign(get_s3_presign_client()))
        query = parse_qs(url.query)

        assert url.netloc == "s3.eu-west-1.amazonaws.com"
        assert url.path == "/output-bucket/tenant/scan/report.zip"
        assert query["X-Amz-Algorithm"] == ["AWS4-HMAC-SHA256"]
        assert "/eu-west-1/s3/aws4_request" in query["X-Amz-Credential"][0]

    @override_settings(
        **{
            **PRESIGN_SETTINGS,
            "DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID": "",
            "DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY": "",
        },
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="",
    )
    def test_region_without_static_keys_signs_with_the_default_chain(self, monkeypatch):
        # An ECS task role reaches boto3 through the default chain, like the env here.
        # A fresh default session keeps these keys from being cached for later tests.
        monkeypatch.setattr(boto3, "DEFAULT_SESSION", None)
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "role-access-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "role-secret-key")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

        query = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert query["X-Amz-Credential"][0].startswith("role-access-key/")
        assert "/eu-west-1/s3/aws4_request" in query["X-Amz-Credential"][0]

    @override_settings(
        **{**PRESIGN_SETTINGS, "DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION": ""},
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="",
        DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL="http://minio:9000",
    )
    def test_internal_endpoint_without_public_endpoint_signs_against_it(self):
        # No browser-reachable host was configured, so the internal one is the best
        # available target instead of falling through to the real AWS host.
        url = urlparse(_presign(get_s3_presign_client()))

        assert url.netloc == "minio:9000"
        assert url.path == "/output-bucket/tenant/scan/report.zip"

    @override_settings(
        **PRESIGN_SETTINGS,
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
        DJANGO_OUTPUT_S3_AWS_ENDPOINT_URL="http://minio:9000",
    )
    def test_public_endpoint_wins_over_the_internal_endpoint(self):
        url = urlparse(_presign(get_s3_presign_client()))

        assert url.netloc == "storage.example.com"

    @override_settings(
        **PRESIGN_SETTINGS,
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_url_targets_the_public_host_in_path_style(self):
        url = urlparse(_presign(get_s3_presign_client()))

        assert url.netloc == "storage.example.com"
        assert url.path == "/output-bucket/tenant/scan/report.zip"

    @override_settings(
        **PRESIGN_SETTINGS,
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_signature_covers_the_public_host(self):
        query = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert query["X-Amz-SignedHeaders"] == ["host"]
        assert "/eu-west-1/s3/aws4_request" in query["X-Amz-Credential"][0]

    @override_settings(
        **PRESIGN_SETTINGS,
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_signature_is_bound_to_the_host_it_was_signed_against(self):
        """Rewriting the host afterwards cannot work, which is why the endpoint is a setting."""
        public = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        with override_settings(
            DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="http://minio:9000"
        ):
            internal = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert public["X-Amz-Signature"] != internal["X-Amz-Signature"]

    @override_settings(
        **{**PRESIGN_SETTINGS, "DJANGO_OUTPUT_S3_AWS_DEFAULT_REGION": ""},
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_region_falls_back_to_the_minio_default(self):
        query = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert "/us-east-1/s3/aws4_request" in query["X-Amz-Credential"][0]

    @override_settings(
        **PRESIGN_SETTINGS,
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_unset_session_token_is_left_out_of_the_url(self):
        """An empty token still reaches the URL as a blank param that storage signs over."""
        url = _presign(get_s3_presign_client())
        query = parse_qs(urlparse(url).query, keep_blank_values=True)

        assert "X-Amz-Security-Token" not in query

    @override_settings(
        **{**PRESIGN_SETTINGS, "DJANGO_OUTPUT_S3_AWS_SESSION_TOKEN": "session-token"},
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_session_token_is_forwarded_when_set(self):
        query = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert query["X-Amz-Security-Token"] == ["session-token"]

    @override_settings(
        **{
            **PRESIGN_SETTINGS,
            "DJANGO_OUTPUT_S3_AWS_ACCESS_KEY_ID": "",
            "DJANGO_OUTPUT_S3_AWS_SECRET_ACCESS_KEY": "",
        },
        DJANGO_OUTPUT_S3_AWS_PUBLIC_ENDPOINT_URL="https://storage.example.com",
    )
    def test_blank_static_credentials_defer_to_the_provider_chain(self, monkeypatch):
        """Empty keys would otherwise be signed as-is, yielding a blank credential scope."""
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "chain-key")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "chain-secret")
        monkeypatch.delenv("AWS_SESSION_TOKEN", raising=False)

        query = parse_qs(urlparse(_presign(get_s3_presign_client())).query)

        assert query["X-Amz-Credential"][0].startswith("chain-key/")
