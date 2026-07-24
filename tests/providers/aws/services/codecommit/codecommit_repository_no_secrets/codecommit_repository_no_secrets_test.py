from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1

AWS_COMMERCIAL_PARTITION = "aws"

repository_name = "test-repo"
repository_arn = f"arn:{AWS_COMMERCIAL_PARTITION}:codecommit:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{repository_name}"


class Test_codecommit_repository_no_secrets:
    def test_no_resources(self):
        """No findings are returned when there are no repositories."""
        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {}
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_repository_no_default_branch(self):
        """A repository without a default branch (e.g. empty repo) passes the check."""
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
            )
        }
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeCommit repository {repository_name} does not have secrets in its default branch."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1
            codecommit_client.get_repository_files_content.assert_not_called()

    def test_repository_no_secrets(self):
        """A repository whose default branch files contain no secrets passes the check."""
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
                default_branch="main",
                default_branch_commit_id="commit-1234",
            )
        }
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}
        codecommit_client.get_repository_files_content.return_value = iter(
            [
                ("README.md", b"# Test repository\n"),
                ("app.py", b"print('hello world')\n"),
            ]
        )

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeCommit repository {repository_name} does not have secrets in its default branch."
            )
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_repository_with_secrets(self):
        """A repository with a hardcoded credential in a tracked file fails the check."""
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
                default_branch="main",
                default_branch_commit_id="commit-1234",
            )
        }
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}
        codecommit_client.get_repository_files_content.return_value = iter(
            [
                ("README.md", b"# Test repository\n"),
                (
                    "src/secrets.py",
                    # Realistic fake JWT that Kingfisher detects. A generic
                    # placeholder value (e.g. a plain "test-password" string)
                    # is suppressed by Kingfisher's low-confidence rules, so a
                    # detectable provider-shaped secret is used instead (same
                    # value used by codebuild's equivalent test).
                    b'AUTH_TOKEN = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"\n',
                ),
            ]
        )

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "src/secrets.py" in result[0].status_extended
            assert "JSON Web Token" in result[0].status_extended
            assert "main" in result[0].status_extended
            assert "commit-1234" in result[0].status_extended
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_repository_with_verified_secret_escalates_severity(self):
        """A verified secret escalates the check severity to critical."""
        from prowler.lib.check.models import Severity
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
                default_branch="main",
                default_branch_commit_id="commit-1234",
            )
        }
        codecommit_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": True,
        }
        codecommit_client.get_repository_files_content.return_value = iter(
            [
                (
                    "src/secrets.py",
                    b'AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"\n',
                ),
            ]
        )

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.detect_secrets_scan_batch",
                return_value={
                    (0, "src/secrets.py"): [
                        {
                            "line_number": 1,
                            "type": "AWS Access Key",
                            "filename": "src/secrets.py",
                            "hashed_secret": "x",
                            "is_verified": True,
                        }
                    ]
                },
            ) as mock_scan,
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            # The check must forward secrets_validate from the config to the scan.
            assert mock_scan.call_args.kwargs.get("validate") is True
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].check_metadata.Severity == Severity.critical
            assert "confirmed to be live" in result[0].status_extended
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_repository_empty_file_content(self):
        """A file with no/empty content is safely skipped and the check still passes."""
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
                default_branch="main",
                default_branch_commit_id="commit-1234",
            )
        }
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}
        codecommit_client.get_repository_files_content.return_value = iter(
            [
                ("empty.txt", b""),
                ("binary.png", None),
            ]
        )

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"

    def test_scan_failure_reports_manual(self):
        """A secret scanner failure is reported as MANUAL, never as a silent PASS."""
        from prowler.lib.utils.utils import SecretsScanError
        from prowler.providers.aws.services.codecommit.codecommit_service import (
            Repository,
        )

        codecommit_client = mock.MagicMock()
        codecommit_client.repositories = {
            repository_arn: Repository(
                repository_id="repo-id-1",
                name=repository_name,
                arn=repository_arn,
                region=AWS_REGION_EU_WEST_1,
                default_branch="main",
                default_branch_commit_id="commit-1234",
            )
        }
        codecommit_client.audit_config = {"secrets_ignore_patterns": []}
        codecommit_client.get_repository_files_content.return_value = iter(
            [
                ("app.py", b"print('hello world')\n"),
            ]
        )

        with (
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_service.CodeCommit",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.codecommit_client",
                codecommit_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.codecommit.codecommit_repository_no_secrets.codecommit_repository_no_secrets import (
                codecommit_repository_no_secrets,
            )

            check = codecommit_repository_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
            assert result[0].resource_id == repository_name
            assert result[0].resource_arn == repository_arn
