from unittest import mock

from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1


class Test_codebuild_project_no_plaintext_credentials:
    def test_no_project(self):
        codebuild_client = mock.MagicMock

        codebuild_client.audit_config = {
            "sensitive_environment_variables": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ]
        }

        codebuild_client.projects = {}

        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
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
            )
        }

        codebuild_client.audit_config = {
            "sensitive_environment_variables": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ]
        }

        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
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
                        "value": "ExampleValue",
                        "type": "PARAMETER_STORE",
                    }
                ],
            )
        }

        codebuild_client.audit_config = {
            "sensitive_environment_variables": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ]
        }

        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
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
            )
        }

        codebuild_client.audit_config = {
            "sensitive_environment_variables": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ]
        }

        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
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
                        "value": "ExampleValue",
                        "type": "PLAINTEXT",
                    }
                ],
            )
        }

        codebuild_client.audit_config = {
            "sensitive_environment_variables": [
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
            ]
        }

        with mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_service.Codebuild",
            codebuild_client,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            codebuild_client,
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "CodeBuild project SensitiveProject has sensitive environment plaintext credentials."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == "SensitiveProject"
            assert result[0].resource_arn == project_arn
