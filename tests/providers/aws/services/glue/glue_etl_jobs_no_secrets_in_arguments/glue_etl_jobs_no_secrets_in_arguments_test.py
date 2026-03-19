from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_glue_etl_jobs_no_secrets_in_arguments:
    @mock_aws
    def test_glue_no_jobs(self):
        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments import (
                    glue_etl_jobs_no_secrets_in_arguments,
                )

                check = glue_etl_jobs_no_secrets_in_arguments()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_glue_job_no_secrets(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        job_name = "test-job"
        job_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:job/{job_name}"
        )
        glue_client.create_job(
            Name=job_name,
            Role="role_test",
            Command={"Name": "name_test", "ScriptLocation": "script_test"},
            DefaultArguments={
                "--enable-continuous-cloudwatch-log": "true",
                "--TempDir": "s3://my-bucket/temp/",
            },
            Tags={"key_test": "value_test"},
            GlueVersion="1.0",
            MaxCapacity=0.0625,
            MaxRetries=0,
            Timeout=10,
            NumberOfWorkers=2,
            WorkerType="G.1X",
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments import (
                    glue_etl_jobs_no_secrets_in_arguments,
                )

                check = glue_etl_jobs_no_secrets_in_arguments()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"No secrets found in Glue job {job_name} default arguments."
                )
                assert result[0].resource_id == job_name
                assert result[0].resource_arn == job_arn
                assert result[0].resource_tags == [{"key_test": "value_test"}]

    @mock_aws
    def test_glue_job_with_secrets(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        job_name = "test-job"
        job_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:job/{job_name}"
        )
        glue_client.create_job(
            Name=job_name,
            Role="role_test",
            Command={"Name": "name_test", "ScriptLocation": "script_test"},
            DefaultArguments={
                "--db-password": "AKIAsupersecretkey1234",
                "--TempDir": "s3://my-bucket/temp/",
            },
            Tags={"key_test": "value_test"},
            GlueVersion="1.0",
            MaxCapacity=0.0625,
            MaxRetries=0,
            Timeout=10,
            NumberOfWorkers=2,
            WorkerType="G.1X",
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments import (
                    glue_etl_jobs_no_secrets_in_arguments,
                )

                check = glue_etl_jobs_no_secrets_in_arguments()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert "Potential secrets found" in result[0].status_extended
                assert job_name in result[0].status_extended
                assert "--db-password" in result[0].status_extended
                assert result[0].resource_id == job_name
                assert result[0].resource_arn == job_arn
                assert result[0].resource_tags == [{"key_test": "value_test"}]

    @mock_aws
    def test_glue_job_empty_arguments(self):
        glue_client = client("glue", region_name=AWS_REGION_US_EAST_1)
        job_name = "test-job"
        job_arn = (
            f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:job/{job_name}"
        )
        glue_client.create_job(
            Name=job_name,
            Role="role_test",
            Command={"Name": "name_test", "ScriptLocation": "script_test"},
            DefaultArguments={},
            Tags={"key_test": "value_test"},
            GlueVersion="1.0",
            MaxCapacity=0.0625,
            MaxRetries=0,
            Timeout=10,
            NumberOfWorkers=2,
            WorkerType="G.1X",
        )

        from prowler.providers.aws.services.glue.glue_service import Glue

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments.glue_client",
                new=Glue(aws_provider),
            ):
                from prowler.providers.aws.services.glue.glue_etl_jobs_no_secrets_in_arguments.glue_etl_jobs_no_secrets_in_arguments import (
                    glue_etl_jobs_no_secrets_in_arguments,
                )

                check = glue_etl_jobs_no_secrets_in_arguments()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"No secrets found in Glue job {job_name} default arguments."
                )
                assert result[0].resource_id == job_name
                assert result[0].resource_arn == job_arn
                assert result[0].resource_tags == [{"key_test": "value_test"}]
