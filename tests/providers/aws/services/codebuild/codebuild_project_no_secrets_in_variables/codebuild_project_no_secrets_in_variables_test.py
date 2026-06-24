from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_codebuild_project_no_secrets_in_variables:
    def test_no_project(self):
        codebuild_client = mock.MagicMock

        codebuild_client.projects = {}

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 0

    def test_project_with_no_envvar(self):
        codebuild_client = mock.MagicMock

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[],
                tags=[],
            )
        }

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject does not have sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_no_plaintext_credentials(self):
        codebuild_client = mock.MagicMock

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "AKIAIOSFODNN7EXAMPLE",
                        "type": "PARAMETER_STORE",
                    }
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject does not have sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_plaintext_credentials_but_not_sensitive(self):
        codebuild_client = mock.MagicMock

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "EXAMPLE_VAR",
                        "value": "ExampleValue",
                        "type": "PLAINTEXT",
                    }
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject does not have sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_sensitive_plaintext_credentials(self):
        codebuild_client = mock.MagicMock

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        # Realistic fake secret that Kingfisher detects. The classic
                        # "AKIAIOSFODNN7EXAMPLE" placeholder is suppressed by
                        # Kingfisher and its AWS Access Key rule is not enabled, so a
                        # detectable provider secret is used instead.
                        "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        "type": "PLAINTEXT",
                    }
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # The JWT paired with a "KEY" variable name yields both a
            # JWT and a Generic API Key finding; order is non-deterministic.
            assert result[0].status_extended.startswith(
                "CodeBuild project SensitiveProject has sensitive environment plaintext credentials in variables:"
            )
            assert (
                "JSON Web Token (base64url-encoded) in variable AWS_ACCESS_KEY_ID"
                in result[0].status_extended
            )
            assert (
                "Generic API Key in variable AWS_ACCESS_KEY_ID"
                in result[0].status_extended
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_sensitive_plaintext_credentials_exluded(self):
        codebuild_client = mock.MagicMock

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_DUMB_ACCESS_KEY",
                        "value": "AKIAIOSFODNN7EXAMPLE",
                        "type": "PLAINTEXT",
                    }
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {
            "excluded_sensitive_environment_variables": ["AWS_DUMB_ACCESS_KEY"]
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject does not have sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_sensitive_plaintext_credentials_excluded_and_not(self):
        codebuild_client = mock.MagicMock()

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_DUMB_ACCESS_KEY",
                        "value": "AKIAIOSFODNN7EXAMPLE",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "AKIAIOSFODNN7EXAMPLE",
                        "type": "PARAMETER_STORE",
                    },
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {
            "excluded_sensitive_environment_variables": ["AWS_DUMB_ACCESS_KEY"]
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject does not have sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_sensitive_plaintext_credentials_excluded_and_failed(self):
        codebuild_client = mock.MagicMock()

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_DUMB_ACCESS_KEY",
                        "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        "type": "PLAINTEXT",
                    },
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {
            "excluded_sensitive_environment_variables": ["AWS_DUMB_ACCESS_KEY"]
        }

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # AWS_DUMB_ACCESS_KEY is excluded, so only AWS_ACCESS_KEY_ID is
            # scanned; its JWT + "KEY" name yields both a JWT and a
            # Generic API Key finding with non-deterministic order.
            assert result[0].status_extended.startswith(
                "CodeBuild project SensitiveProject has sensitive environment plaintext credentials in variables:"
            )
            assert (
                "JSON Web Token (base64url-encoded) in variable AWS_ACCESS_KEY_ID"
                in result[0].status_extended
            )
            assert (
                "Generic API Key in variable AWS_ACCESS_KEY_ID"
                in result[0].status_extended
            )
            assert "AWS_DUMB_ACCESS_KEY" not in result[0].status_extended
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []

    def test_project_with_multiple_sensitive_credentials(self):
        codebuild_client = mock.MagicMock()

        from prowler.providers.aws.services.codebuild.codebuild_service import Project

        project_arn = f"arn:aws:codebuild:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:project/SensitiveProject"
        codebuild_client.projects = {
            project_arn: Project(
                name="SensitiveProject",
                arn=project_arn,
                region=AWS_REGION_US_EAST_1,
                last_invoked_time=None,
                buildspec=None,
                environment_variables=[
                    {
                        "name": "AWS_DUMB_ACCESS_KEY",
                        "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        "type": "PLAINTEXT",
                    },
                    {
                        "name": "AWS_ACCESS_KEY_ID",
                        "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        "type": "PLAINTEXT",
                    },
                ],
                tags=[],
            )
        }

        codebuild_client.audit_config = {"excluded_sensitive_environment_variables": []}

        with (
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
                codebuild_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables.codebuild_client",
                codebuild_client,
            ),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_secrets_in_variables.codebuild_project_no_secrets_in_variables import (
                codebuild_project_no_secrets_in_variables,
            )

            check = codebuild_project_no_secrets_in_variables()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            # Both variables hold a JWT and have "KEY" in their name, so
            # each yields a JWT and a Generic API Key finding; order is
            # non-deterministic.
            assert result[0].status_extended.startswith(
                "CodeBuild project SensitiveProject has sensitive environment plaintext credentials in variables:"
            )
            for var_name in ("AWS_DUMB_ACCESS_KEY", "AWS_ACCESS_KEY_ID"):
                assert (
                    f"JSON Web Token (base64url-encoded) in variable {var_name}"
                    in result[0].status_extended
                )
                assert (
                    f"Generic API Key in variable {var_name}"
                    in result[0].status_extended
                )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == []
