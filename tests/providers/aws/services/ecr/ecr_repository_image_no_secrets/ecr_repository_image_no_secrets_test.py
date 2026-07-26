from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import (
    ImageDetails,
    ImageScanData,
    ImageScanFile,
    Registry,
    Repository,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

# A real JWT: Kingfisher detects this regardless of the surrounding key name
# or format (env-style KEY=value, Dockerfile RUN step, or source file).
SECRET_VALUE = (
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9"
    ".eyJzdWIiOiIxMjM0NTY3ODkwIn0"
    ".dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
)


def create_repository(name="test-repo", region=AWS_REGION_US_EAST_1) -> Repository:
    return Repository(
        name=name,
        arn=f"arn:aws:ecr:{region}:{AWS_ACCOUNT_NUMBER}:repository/{name}",
        region=region,
        scan_on_push=True,
        images_details=[],
    )


def create_image(tag="latest", digest=None) -> ImageDetails:
    return ImageDetails(
        latest_tag=tag,
        latest_digest=digest or f"sha256:{'0' * 64}",
        image_pushed_at=datetime.now(),
        scan_findings_status=None,
        scan_findings_severity_count=None,
        artifact_media_type="application/vnd.docker.container.image.v1+json",
        type="Docker",
    )


def mock_image_scan_data(pairs):
    def _generator():
        for entry in pairs:
            yield entry

    return _generator


class Test_ecr_repository_image_no_secrets:
    def test_no_repositories(self):
        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data([])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_clean_image(self):
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=["PATH=/usr/bin"],
            history=["RUN echo hello"],
            files=[],
            truncated=False,
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            digest_short = image.latest_digest.split(":")[-1][:12]
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                f"No secrets found in the image '{image.latest_tag}' "
                f"({image.latest_digest}) of ECR repository {repository.name}."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_id
                == f"{repository.name}:{image.latest_tag}@{digest_short}"
            )
            assert result[0].resource_arn == f"{repository.arn}/image/{digest_short}"

    def test_truncated_image_still_passes_with_disclosure(self):
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(env=[], history=[], files=[], truncated=True)

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                "Some layers or files exceeded configured size limits and were "
                "not scanned." in result[0].status_extended
            )

    def test_secret_in_environment_variable(self):
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=["PATH=/usr/bin", f"DB_PASSWORD={SECRET_VALUE}"],
            history=[],
            files=[],
            truncated=False,
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "environment variable DB_PASSWORD" in result[0].status_extended

    def test_secret_in_build_history(self):
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=[],
            history=["RUN apt-get update", f'RUN export TOKEN="{SECRET_VALUE}"'],
            files=[],
            truncated=False,
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "image history step 2" in result[0].status_extended

    def test_secret_in_layer_file(self):
        repository = create_repository()
        image = create_image()
        layer_digest = f"sha256:{'a' * 64}"
        scan_data = ImageScanData(
            env=[],
            history=[],
            files=[
                ImageScanFile(
                    path="app/config.py",
                    layer_digest=layer_digest,
                    content=f'TOKEN = "{SECRET_VALUE}"',
                )
            ],
            truncated=False,
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "file app/config.py" in result[0].status_extended
            assert layer_digest in result[0].status_extended

    def test_manifest_unresolvable(self):
        repository = create_repository()
        image = create_image()

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, None)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
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
                "Could not resolve or retrieve the manifest"
                in result[0].status_extended
            )

    def test_scan_error_reports_manual_for_every_image(self):
        from prowler.lib.utils.utils import SecretsScanError

        repository = create_repository()
        image = create_image()
        repository.images_details = [image]
        registry = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_US_EAST_1,
            repositories=[repository],
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {AWS_REGION_US_EAST_1: registry}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        # Not consumed on this path, but must be a real generator to iterate.
        ecr_client._get_image_scan_data = mock_image_scan_data([])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Scanner failure"),
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan image" in result[0].status_extended
            assert "Scanner failure" in result[0].status_extended

    def test_verified_secret_escalates_to_critical(self):
        from prowler.lib.check.models import Severity

        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=[f"TOKEN={SECRET_VALUE}"], history=[], files=[], truncated=False
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": True,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, image, scan_data)]
        )

        def fake_scan_batch(payloads, **kwargs):
            # The real detect_secrets_scan_batch consumes the lazily-yielded
            # payloads generator as a side effect (that's what populates the
            # check's `scanned` list); replicate that here while returning
            # a controlled, pre-verified finding.
            list(payloads)
            return {
                (0, "environment"): [
                    {
                        "type": "JSON Web Token (base64url-encoded)",
                        "line_number": 2,
                        "is_verified": True,
                    }
                ]
            }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.detect_secrets_scan_batch",
                side_effect=fake_scan_batch,
            ) as mock_scan,
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert mock_scan.call_args.kwargs.get("validate") is True
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended

    def test_multiple_repositories_and_images(self):
        repo1 = create_repository(name="repo-1")
        repo2 = create_repository(name="repo-2")
        image1 = create_image(tag="v1", digest=f"sha256:{'1' * 64}")
        image2 = create_image(tag="v2", digest=f"sha256:{'2' * 64}")

        clean_scan = ImageScanData(env=[], history=[], files=[], truncated=False)
        fail_scan = ImageScanData(
            env=[f"DB_PASSWORD={SECRET_VALUE}"],
            history=[],
            files=[],
            truncated=False,
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repo1, image1, clean_scan), (repo2, image2, fail_scan)]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider(),
            ),
            mock.patch(
                "prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets.ecr_client",
                new=ecr_client,
            ),
        ):
            from prowler.providers.aws.services.ecr.ecr_repository_image_no_secrets.ecr_repository_image_no_secrets import (
                ecr_repository_image_no_secrets,
            )

            check = ecr_repository_image_no_secrets()
            result = check.execute()

            assert len(result) == 2
            statuses_by_repo = {r.resource_id.split(":")[0]: r.status for r in result}
            assert statuses_by_repo["repo-1"] == "PASS"
            assert statuses_by_repo["repo-2"] == "FAIL"
