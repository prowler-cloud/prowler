from datetime import datetime
from unittest import mock

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
