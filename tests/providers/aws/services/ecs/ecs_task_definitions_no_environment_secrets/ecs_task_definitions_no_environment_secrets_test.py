from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

TASK_NAME = "test-task"
TASK_REVISION = "1"
CONTAINER_NAME = "test-container"
ENV_VAR_NAME_NO_SECRETS = "host"
ENV_VAR_VALUE_NO_SECRETS = "localhost:1234"
ENV_VAR_NAME_WITH_KEYWORD = "DB_PASSWORD"
# Realistic fake secrets that Kingfisher actually detects (placeholders such as
# the previous "srv://admin:pass@db" basic-auth URL are no longer flagged).
# A JWT fires on any line of the dumped JSON (even when followed by a
# trailing comma); a keyword-named variable additionally fires the generic
# keyword rule when it is the last entry in the dump.
ENV_VAR_VALUE_WITH_SECRETS = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
ENV_VAR_NAME_WITH_KEYWORD2 = "DATABASE_PASSWORD"
ENV_VAR_VALUE_WITH_SECRETS2 = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI5ODc2NTQzMjEwIiwibmFtZSI6IkphbmUifQ.s5LqY8mC2pX1vN0bQwReTyUiOpAsDfGhJkLzXcVbNm0"
# Generic password/secret assignment value (detected only on the last entry of
# the JSON dump, where there is no trailing comma after the value).
ENV_VAR_VALUE_GENERIC_SECRET = "Tr0ub4dor3xKq9vLmZ"


class Test_ecs_task_definitions_no_environment_secrets:
    def test_no_task_definitions(self):
        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_container_env_var_no_secrets(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_NO_SECRETS,
                            "value": ENV_VAR_VALUE_NO_SECRETS,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in variables of ECS task definition {TASK_NAME} with revision {TASK_REVISION}."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_env_var_with_secret(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_NO_SECRETS,
                            "value": ENV_VAR_VALUE_WITH_SECRETS,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> JSON Web Token (base64url-encoded) on the environment variable host."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_env_var_with_keyword(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_WITH_KEYWORD,
                            "value": ENV_VAR_VALUE_GENERIC_SECRET,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> Generic Password on the environment variable DB_PASSWORD."
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_env_var_with_keyword_and_secret(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
                    "environment": [
                        {
                            "name": ENV_VAR_NAME_WITH_KEYWORD,
                            "value": ENV_VAR_VALUE_WITH_SECRETS,
                        }
                    ],
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            # The keyword-named variable holding a real secret triggers both the
            # generic keyword rule and the JWT rule on the same line.
            # Kingfisher emits same-line findings in a non-deterministic order, so
            # assert both are present without pinning their order.
            assert result[0].status_extended.startswith(
                f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> "
            )
            assert (
                "JSON Web Token (base64url-encoded) on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert (
                "Generic Password on the environment variable DB_PASSWORD"
                in result[0].status_extended
            )
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_multiple_env_vars_with_keyword_and_secret(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
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
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            # DB_PASSWORD holds a JWT under a keyword name, so it fires
            # both the JWT rule and the generic keyword rule on the
            # same line (non-deterministic order); host holds a second JWT.
            assert result[0].status_extended.startswith(
                f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> "
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
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_container_all_env_vars_with_keyword_and_secret(self):
        ecs_client = client("ecs", region_name=AWS_REGION_US_EAST_1)

        task_arn = ecs_client.register_task_definition(
            family=TASK_NAME,
            containerDefinitions=[
                {
                    "name": CONTAINER_NAME,
                    "image": "ubuntu",
                    "memory": 128,
                    "readonlyRootFilesystem": True,
                    "privileged": False,
                    "user": "appuser",
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
                }
            ],
        )["taskDefinition"]["taskDefinitionArn"]

        from prowler.providers.aws.services.ecs.ecs_service import ECS

        mocked_aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=mocked_aws_provider,
            ),
            patch(
                "prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets.ecs_client",
                new=ECS(mocked_aws_provider),
            ),
        ):
            from prowler.providers.aws.services.ecs.ecs_task_definitions_no_environment_secrets.ecs_task_definitions_no_environment_secrets import (
                ecs_task_definitions_no_environment_secrets,
            )

            check = ecs_task_definitions_no_environment_secrets()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            # DB_PASSWORD holds a JWT under a keyword name, so it fires
            # both the JWT and the generic keyword rule on the same line
            # (non-deterministic order); DATABASE_PASSWORD fires the generic
            # keyword rule on its own line.
            assert result[0].status_extended.startswith(
                f"Potential secrets found in ECS task definition {TASK_NAME} with revision {TASK_REVISION}: Secrets in container test-container -> "
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
            assert result[0].resource_id == f"{TASK_NAME}:{TASK_REVISION}"
            assert result[0].resource_arn == task_arn
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
