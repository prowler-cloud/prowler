from unittest import mock
from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.batch.batch_service import (
    BatchContainerProperties,
    BatchJobDefinition,
    ContainerEnvVariable,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

JOB_NAME = "test-batch-job"
JOB_REVISION = 1
ENV_VAR_NAME_NO_SECRETS = "host"
ENV_VAR_VALUE_NO_SECRETS = "localhost:1234"
ENV_VAR_NAME_WITH_KEYWORD = "DB_PASSWORD"
# Realistic fake secrets that Kingfisher actually detects.
ENV_VAR_VALUE_WITH_SECRETS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
ENV_VAR_NAME_WITH_KEYWORD2 = "DATABASE_PASSWORD"
ENV_VAR_VALUE_WITH_SECRETS2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6IkphbmUifQ.s5LqY8mC2pX1vN0bQwReTyUiOpAsDfGhJkLzXcVbNm0"
ENV_VAR_VALUE_GENERIC_SECRET = "Tr0ub4dor3xKq9vLmZ"


class Test_batch_job_definition_no_secrets:
    def test_no_job_definitions(self):
        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_job_definition_env_var_no_secrets(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "environment": [
                    {
                        "name": ENV_VAR_NAME_NO_SECRETS,
                        "value": ENV_VAR_VALUE_NO_SECRETS,
                    }
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}."
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_env_var_with_secret(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "environment": [
                    {
                        "name": ENV_VAR_NAME_NO_SECRETS,
                        "value": ENV_VAR_VALUE_WITH_SECRETS,
                    }
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Potential secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}:"
                in result[0].status_extended
            )
            assert (
                "JSON Web Token (base64url-encoded) on the environment variable host"
                in result[0].status_extended
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_env_var_with_keyword(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "environment": [
                    {
                        "name": ENV_VAR_NAME_WITH_KEYWORD,
                        "value": ENV_VAR_VALUE_GENERIC_SECRET,
                    }
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Potential secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}:"
                in result[0].status_extended
            )
            assert (
                "Generic Password on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_no_env_vars(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}."
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_command_with_secret(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "command": [
                    "python",
                    "app.py",
                    "--token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Potential secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}:"
                in result[0].status_extended
            )
            assert "Secrets in command" in result[0].status_extended
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_command_no_secrets(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "command": ["python", "app.py"],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}."
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_multiple_env_vars_with_secrets(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "environment": [
                    {
                        "name": ENV_VAR_NAME_WITH_KEYWORD,
                        "value": ENV_VAR_VALUE_WITH_SECRETS,
                    },
                    {
                        "name": ENV_VAR_NAME_NO_SECRETS,
                        "value": ENV_VAR_VALUE_WITH_SECRETS2,
                    },
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Potential secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}:"
                in result[0].status_extended
            )
            assert (
                "JSON Web Token (base64url-encoded) on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert (
                "Generic Password on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert (
                "JSON Web Token (base64url-encoded) on the environment variable host"
                in result[0].status_extended
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_job_definition_all_env_vars_with_keyword_and_secret(self):
        batch_client = client("batch", region_name=AWS_REGION_US_EAST_1)

        response = batch_client.register_job_definition(
            jobDefinitionName=JOB_NAME,
            type="container",
            containerProperties={
                "image": "test-image:latest",
                "memory": 128,
                "vcpus": 1,
                "environment": [
                    {
                        "name": ENV_VAR_NAME_WITH_KEYWORD,
                        "value": ENV_VAR_VALUE_WITH_SECRETS,
                    },
                    {
                        "name": ENV_VAR_NAME_WITH_KEYWORD2,
                        "value": ENV_VAR_VALUE_GENERIC_SECRET,
                    },
                ],
            },
        )
        job_arn = response["jobDefinitionArn"]

        from prowler.providers.aws.services.batch.batch_service import Batch

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                new=Batch(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                f"Potential secrets found in Batch job definition {JOB_NAME} with revision {JOB_REVISION}:"
                in result[0].status_extended
            )
            assert (
                "JSON Web Token (base64url-encoded) on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert (
                "Generic Password on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert (
                "Generic Password on the environment variable DATABASE_PASSWORD"
                in result[0].status_extended
            )
            assert result[0].resource_id == f"{JOB_NAME}:{JOB_REVISION}"
            assert result[0].resource_arn == job_arn
            assert result[0].region == AWS_REGION_US_EAST_1

    def test_scan_failure_reports_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        batch_client = mock.MagicMock()
        job_definition_arn = f"arn:aws:batch:{AWS_REGION_US_EAST_1}:123456789012:job-definition/{JOB_NAME}:1"
        batch_client.job_definitions = {
            job_definition_arn: BatchJobDefinition(
                name=JOB_NAME,
                arn=job_definition_arn,
                revision=JOB_REVISION,
                region=AWS_REGION_US_EAST_1,
                container_properties=BatchContainerProperties(
                    image="test-image:latest",
                    command=[],
                    environment=[
                        ContainerEnvVariable(name="DB_PASSWORD", value="pass-12343")
                    ],
                ),
            )
        }
        batch_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
            ),
            mock.patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
                batch_client,
            ),
            mock.patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Kingfisher exited with code 1"),
            ),
        ):
            from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
                batch_job_definition_no_secrets,
            )

            check = batch_job_definition_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "Could not scan" in result[0].status_extended
