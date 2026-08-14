import io
import tarfile
from datetime import datetime
from unittest import mock

from prowler.lib.utils.utils import SecretsScanError
from prowler.providers.aws.services.ecr.ecr_service import (
    FindingSeverityCounts,
    ImageDetails,
    Registry,
    Repository,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_provider,
)

repository_name = "test_repo"
repository_arn = (
    f"arn:aws:ecr:eu-west-1:{AWS_ACCOUNT_NUMBER}:repository/{repository_name}"
)
latest_tag = "test-tag"
latest_digest = "test-digest"
docker_container_image_artifact_media_type = (
    "application/vnd.docker.container.image.v1+json"
)


def _build_tar(members):
    """Build an in-memory tar archive from a name -> bytes mapping."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class Test_ecr_repository_image_no_secrets:
    def test_no_registries(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 0

    def test_repository_no_images(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[],
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}
        ecr_client.regional_clients = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 0

    def test_image_no_secrets(self):
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
        ):
            mock_response = mock.MagicMock()
            mock_response.read.return_value = b"some safe content without secrets"
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "No secrets found" in result[0].status_extended
                and repository_name in result[0].status_extended
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_image_collection_returns_no_data_reports_manual(self):
        """When image collection fails the check should report MANUAL, not PASS."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        # batch_get_image returns no images -> image collection fails
        mock_regional_client.batch_get_image.return_value = {"images": []}
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "Could not collect image data" in result[0].status_extended
                and repository_name in result[0].status_extended
            )
            assert result[0].resource_id == repository_name

    def test_no_resources(self):
        """When no repositories have images the check should return empty findings."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=None,
                )
            ],
            rules=[],
        )
        ecr_client.audit_config = {}
        ecr_client.regional_clients = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 0

    def test_scanner_error_reports_manual(self):
        """When detect_secrets_scan_batch raises SecretsScanError, all
        repositories should report MANUAL."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Scanner binary not found"),
            ),
        ):
            mock_response = mock.MagicMock()
            mock_response.read.return_value = b"some safe content without secrets"
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "Could not scan" in result[0].status_extended
                and repository_name in result[0].status_extended
            )
            assert result[0].resource_id == repository_name

    def test_image_with_secrets(self):
        """When secrets are found the check should report FAIL with image digest."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
        ):
            mock_response = mock.MagicMock()
            mock_response.read.return_value = b"some safe content without secrets"
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            def _mock_scan(payloads, **kwargs):
                # Consume the generator so the check tracks which repos
                # had image data collected, then return simulated findings.
                list(payloads)
                return {
                    (0, "config-sha256:config123"): [
                        {"type": "AWS Access Key", "line_number": 1},
                    ]
                }

            with mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=_mock_scan,
            ):
                check = ecr_repository_image_no_secrets()
                result = check.execute()
                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    repository_name in result[0].status_extended
                    and latest_digest in result[0].status_extended
                )
                assert result[0].resource_id == repository_name
                assert result[0].resource_arn == repository_arn
                assert result[0].region == AWS_REGION_EU_WEST_1

    def test_image_oversized_tar_member_reports_manual(self):
        """A layer member at/above MAX_TAR_MEMBER_SIZE must report MANUAL, not PASS."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {}

        def _mock_scan(payloads, **kwargs):
            # Consume the generator so collection state (including the
            # incomplete-member marker) is recorded before aggregation.
            list(payloads)
            return {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=_mock_scan,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                MAX_TAR_MEMBER_SIZE,
                ecr_repository_image_no_secrets,
            )

            # A layer tar containing a single member at the size limit is not
            # fully scanned, so the repository must not be reported as PASS.
            layer_data = _build_tar({"large.bin": b"x" * MAX_TAR_MEMBER_SIZE})
            mock_response = mock.MagicMock()
            mock_response.read.return_value = layer_data
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                "Could not collect image data" in result[0].status_extended
                and repository_name in result[0].status_extended
            )
            assert result[0].resource_id == repository_name

    def test_image_tar_member_below_max_size_reports_pass(self):
        """A tar member just below MAX_TAR_MEMBER_SIZE must be scanned fully and report PASS."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                return_value={},
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                MAX_TAR_MEMBER_SIZE,
                ecr_repository_image_no_secrets,
            )

            # A layer tar with a member just below the size limit must be
            # fully scanned and report PASS.
            layer_data = _build_tar({"small.bin": b"x" * (MAX_TAR_MEMBER_SIZE - 1)})
            mock_response = mock.MagicMock()
            mock_response.read.return_value = layer_data
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == repository_name

    def test_image_secrets_ignore_files_exclude_members(self):
        """Layer members matching secrets_ignore_files must be excluded from the scan."""
        ecr_client = mock.MagicMock
        ecr_client.registries = {}
        ecr_client.registries[AWS_REGION_EU_WEST_1] = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_EU_WEST_1,
            scan_type="BASIC",
            repositories=[
                Repository(
                    name=repository_name,
                    arn=repository_arn,
                    region=AWS_REGION_EU_WEST_1,
                    scan_on_push=True,
                    images_details=[
                        ImageDetails(
                            latest_tag=latest_tag,
                            latest_digest=latest_digest,
                            image_pushed_at=datetime(2023, 1, 1),
                            scan_findings_status="COMPLETE",
                            scan_findings_severity_count=FindingSeverityCounts(
                                critical=0, high=0, medium=0
                            ),
                            artifact_media_type=docker_container_image_artifact_media_type,
                            type="Docker",
                        )
                    ],
                )
            ],
            rules=[],
        )

        mock_regional_client = mock.MagicMock()
        mock_regional_client.batch_get_image.return_value = {
            "images": [
                {
                    "imageManifest": '{"config": {"digest": "sha256:config123"}, "layers": [{"digest": "sha256:layer123"}]}'
                }
            ]
        }
        mock_regional_client.get_download_url_for_layer.return_value = {
            "downloadUrl": "https://example.com/layer"
        }
        ecr_client.regional_clients = {
            AWS_REGION_EU_WEST_1: mock_regional_client
        }
        ecr_client.audit_config = {"secrets_ignore_files": ["*.deps.json"]}

        layer_data = _build_tar(
            {
                "app/code.py": b"print('hello')",
                "app/hidden.deps.json": b"password = 'sup3rs3cret'",
            }
        )

        def _mock_scan(payloads, **kwargs):
            seen = list(payloads)
            # The excluded member must not be handed to the detector.
            assert all(
                "hidden.deps.json" not in key[1] for key, _ in seen
            ), f"ignored member should not be scanned: {seen}"
            # The non-excluded member must be handed to the detector.
            assert any(
                "app/code.py" in key[1] for key, _ in seen
            ), f"expected member not found in scan payload: {seen}"
            # No findings, so the repository reports PASS. Even though the tar
            # contains secret-like content in an ignored member, that member is
            # excluded before the detector runs.
            return {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                ecr_client,
            ),
            mock.patch("urllib.request.urlopen") as mock_urlopen,
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=_mock_scan,
            ),
        ):
            mock_response = mock.MagicMock()
            mock_response.read.return_value = layer_data
            mock_response.__enter__ = mock.MagicMock(return_value=mock_response)
            mock_response.__exit__ = mock.MagicMock(return_value=False)
            mock_urlopen.return_value = mock_response

            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert repository_name in result[0].status_extended
            assert result[0].resource_id == repository_name
