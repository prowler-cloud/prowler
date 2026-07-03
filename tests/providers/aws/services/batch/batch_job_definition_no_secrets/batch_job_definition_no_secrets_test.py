from unittest import mock

from prowler.providers.aws.services.batch.batch_service import (
    JobDefinition,
    JobDefinitionContainer,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_batch_job_definition_no_secrets:
    def test_no_job_definitions(self):
        batch_client = mock.MagicMock()
        batch_client.job_definitions = {}
        batch_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(batch_client)

        assert len(result) == 0

    def test_job_definition_no_secrets(self):
        jd = _build_job_definition(
            containers=[
                JobDefinitionContainer(
                    name="containerProperties",
                    environment=[{"name": "env_key", "value": "env_val"}],
                    command=["echo", "hello"],
                )
            ]
        )
        batch_client = mock.MagicMock()
        batch_client.job_definitions = {jd.arn: jd}
        batch_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(batch_client)

        assert len(result) == 1
        assert result[0].status == "PASS"
        assert (
            result[0].status_extended
            == f"No secrets found in Batch job definition {jd.name}."
        )
        assert result[0].region == AWS_REGION_US_EAST_1
        assert result[0].resource_id == f"{jd.name}:{jd.revision}"
        assert result[0].resource_arn == jd.arn

    def test_job_definition_with_secrets_in_env(self):
        jd = _build_job_definition(
            containers=[
                JobDefinitionContainer(
                    name="containerProperties",
                    environment=[
                        {
                            "name": "db_pass",
                            "value": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U",
                        }
                    ],
                    command=["echo", "hello"],
                )
            ]
        )
        batch_client = mock.MagicMock()
        batch_client.job_definitions = {jd.arn: jd}
        batch_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(batch_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "container 'containerProperties' environment variable 'db_pass'"
            in result[0].status_extended
        )

    def test_job_definition_with_secrets_in_command(self):
        jd = _build_job_definition(
            containers=[
                JobDefinitionContainer(
                    name="containerProperties",
                    environment=[],
                    command=[
                        "export JWT=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
                    ],
                )
            ]
        )
        batch_client = mock.MagicMock()
        batch_client.job_definitions = {jd.arn: jd}
        batch_client.audit_config = {"secrets_ignore_patterns": []}

        result = _execute_check(batch_client)

        assert len(result) == 1
        assert result[0].status == "FAIL"
        assert (
            "container 'containerProperties' command parameter at index 0"
            in result[0].status_extended
        )

    def test_job_definition_scan_error_marks_manual(self):
        from prowler.lib.utils.utils import SecretsScanError

        jd = _build_job_definition(
            containers=[
                JobDefinitionContainer(
                    name="containerProperties",
                    environment=[{"name": "env_key", "value": "env_val"}],
                    command=["echo", "hello"],
                )
            ]
        )
        batch_client = mock.MagicMock()
        batch_client.job_definitions = {jd.arn: jd}
        batch_client.audit_config = {"secrets_ignore_patterns": []}

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.detect_secrets_scan_batch",
                side_effect=SecretsScanError("Scanner failure"),
            ),
        ):
            result = _execute_check(batch_client)

        assert len(result) == 1
        assert result[0].status == "MANUAL"
        assert (
            f"Could not scan Batch job definition {jd.name} for secrets: Scanner failure; manual review is required."
            in result[0].status_extended
        )


def _build_job_definition(containers: list) -> JobDefinition:
    jd_name = "test-job-def"
    jd_arn = (
        f"arn:aws:batch:{AWS_REGION_US_EAST_1}:"
        f"{AWS_ACCOUNT_NUMBER}:job-definition/{jd_name}:1"
    )
    return JobDefinition(
        name=jd_name,
        arn=jd_arn,
        revision=1,
        region=AWS_REGION_US_EAST_1,
        containers=containers,
        tags=[],
    )


def _execute_check(batch_client):
    aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(
            "prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets.batch_client",
            batch_client,
        ),
    ):
        from prowler.providers.aws.services.batch.batch_job_definition_no_secrets.batch_job_definition_no_secrets import (
            batch_job_definition_no_secrets,
        )

        check = batch_job_definition_no_secrets()
        return check.execute()
