from datetime import datetime
from unittest import mock

from prowler.providers.aws.services.ecr.ecr_service import (
    ImageDetails,
    Registry,
    Repository,
)
from prowler.providers.aws.services.ecr.image_inspection import (
    ImageScanData,
    ImageScanFile,
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
    """Build a minimal ECR Repository fixture."""
    return Repository(
        name=name,
        arn=f"arn:aws:ecr:{region}:{AWS_ACCOUNT_NUMBER}:repository/{name}",
        region=region,
        scan_on_push=True,
        images_details=[],
    )


def create_image(tag="latest", digest=None) -> ImageDetails:
    """Build a minimal ImageDetails fixture."""
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
    """Build a fake _get_image_scan_data generator yielding the given pairs."""

    def _generator():
        """Yield each (repository, image, scan_data) pair once."""
        for entry in pairs:
            yield entry

    return _generator


class Test_ecr_repository_image_no_secrets:
    """Tests for the ecr_repository_image_no_secrets check."""

    def test_no_repositories(self):
        """No repositories yields no findings."""
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
        """An image with no secrets passes."""
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

    def test_truncated_image_reports_manual(self):
        """A clean but truncated image is MANUAL, since part was not scanned."""
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
            assert result[0].status == "MANUAL"
            assert (
                "part of it could not be retrieved or exceeded configured size "
                "limits and was not scanned" in result[0].status_extended
            )

    def test_secret_in_environment_variable(self):
        """A secret in an environment variable fails, naming the variable."""
        from prowler.lib.check.models import Severity

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
            assert SECRET_VALUE not in result[0].status_extended
            assert result[0].check_metadata.Severity == Severity.high

    def test_secret_in_malformed_env_entry_is_redacted(self):
        """An env entry without '=' is reported generically, never echoed."""
        repository = create_repository()
        image = create_image()
        # The entry has no "=" so no variable name can be split out; the entry
        # itself is the secret and must not appear in the finding.
        scan_data = ImageScanData(
            env=[SECRET_VALUE],
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
            assert "in image environment variables" in result[0].status_extended
            assert SECRET_VALUE not in result[0].status_extended

    def test_secret_in_unsafe_environment_name_is_redacted(self):
        """An unsafe name before '=' is never included in report text."""
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=[f"{SECRET_VALUE}=safe-value"],
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

            result = ecr_repository_image_no_secrets().execute()

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert "in image environment variables" in result[0].status_extended
        assert SECRET_VALUE not in str(vars(result[0]))

    def test_scanned_file_content_is_freed_after_execute(self):
        """File contents are released after scanning so memory stays flat."""
        repository = create_repository()
        image = create_image()
        scanned_file = ImageScanFile(
            path="app/config.py",
            layer_digest=f"sha256:{'a' * 64}",
            content="nothing secret here",
        )
        scan_data = ImageScanData(
            env=[], history=[], files=[scanned_file], truncated=False
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
            assert result[0].status == "PASS"
            # The check empties each file's content once it is handed to the
            # scanner; only path and layer digest are needed thereafter.
            assert scanned_file.content == ""

    def test_secrets_ignore_patterns_suppresses_finding(self):
        """A secret matching an ignore pattern is suppressed."""
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
            "secrets_ignore_patterns": [SECRET_VALUE],
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

    def test_secret_in_build_history(self):
        """A secret in a build history step fails, naming the step."""
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
            assert SECRET_VALUE not in result[0].status_extended

    def test_multiline_environment_secret_keeps_entry_attribution(self):
        """Embedded newlines do not shift an env finding to another entry."""
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=[f"MULTILINE=prefix\r\n{SECRET_VALUE}", "WRONG=value"],
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

            result = ecr_repository_image_no_secrets().execute()

        assert "environment variable MULTILINE" in result[0].status_extended
        assert "environment variable WRONG" not in result[0].status_extended

    def test_multiline_history_secret_keeps_step_attribution(self):
        """Embedded newlines do not shift a history finding to another step."""
        repository = create_repository()
        image = create_image()
        scan_data = ImageScanData(
            env=[],
            history=[f"RUN first\nexport TOKEN={SECRET_VALUE}", "RUN second"],
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

            result = ecr_repository_image_no_secrets().execute()

        assert "image history step 1" in result[0].status_extended
        assert "image history step 2" not in result[0].status_extended

    def test_secret_in_layer_file(self):
        """A secret in a layer file fails, naming the file and layer."""
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
            assert SECRET_VALUE not in result[0].status_extended

    def test_manifest_unresolvable(self):
        """An unresolvable manifest is reported as MANUAL."""
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

    def test_latest_image_lookup_error_reports_repository_manual(self):
        """A failed authoritative image lookup is reported for the repository."""
        repository = create_repository()
        lookup_error = RuntimeError("authoritative lookup failed")
        ecr_client = mock.MagicMock()
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        ecr_client._get_image_scan_data = mock_image_scan_data(
            [(repository, None, lookup_error)]
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

            result = ecr_repository_image_no_secrets().execute()

        assert result[0].status == "MANUAL"
        assert "Could not determine the latest image" in result[0].status_extended

    def test_scan_error_reports_manual_for_latest_image_per_repository(self):
        """A scanner failure reports MANUAL once per repository's latest image."""
        from prowler.lib.utils.utils import SecretsScanError

        # Each repository has multiple images; the scan-error fallback must
        # scope to the latest image per repository only, mirroring the
        # success-path scope, not emit one MANUAL per image.
        repo1 = create_repository(name="repo-1")
        repo1.images_details = [
            create_image(tag="v1", digest=f"sha256:{'1' * 64}"),
            create_image(tag="v2", digest=f"sha256:{'2' * 64}"),
        ]
        repo2 = create_repository(name="repo-2")
        repo2.images_details = [
            create_image(tag="v1", digest=f"sha256:{'3' * 64}"),
            create_image(tag="v2", digest=f"sha256:{'4' * 64}"),
        ]
        registry = Registry(
            id=AWS_ACCOUNT_NUMBER,
            arn=f"arn:aws:ecr:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:registry/{AWS_ACCOUNT_NUMBER}",
            region=AWS_REGION_US_EAST_1,
            repositories=[repo1, repo2],
        )

        ecr_client = mock.MagicMock()
        ecr_client.registries = {AWS_REGION_US_EAST_1: registry}
        ecr_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        # Not consumed on this path, but must be a real generator to iterate.
        ecr_client._get_image_scan_data = mock_image_scan_data([])
        # The error fallback resolves each repository's scan target via
        # _get_scan_target_image; mirror the real method's latest-image scope.
        ecr_client._get_scan_target_image.side_effect = lambda repository: (
            repository.images_details[-1] if repository.images_details else None
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

            # One MANUAL per repository (its latest image), not one per image.
            assert len(result) == 2
            for report in result:
                assert report.status == "MANUAL"
                assert "Could not scan image" in report.status_extended
                assert "Scanner failure" in report.status_extended

            digests_reported = {report.resource_id.split("@")[-1] for report in result}
            latest_digest_repo1 = repo1.images_details[-1].latest_digest.split(":")[-1][
                :12
            ]
            latest_digest_repo2 = repo2.images_details[-1].latest_digest.split(":")[-1][
                :12
            ]
            assert digests_reported == {latest_digest_repo1, latest_digest_repo2}
            assert "Scanner failure" in result[0].status_extended

    def test_verified_secret_escalates_to_critical(self):
        """A verified secret escalates severity to critical."""
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
            """Drain the payload generator like the real scanner, then return canned findings."""
            list(payloads)
            return {
                (0, "environment:0"): [
                    {
                        "type": "JSON Web Token (base64url-encoded)",
                        "line_number": 1,
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
        """Mixed pass/fail results are reported across multiple repositories."""
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
            report_by_repo = {r.resource_id.split(":")[0]: r for r in result}
            assert SECRET_VALUE not in report_by_repo["repo-2"].status_extended
