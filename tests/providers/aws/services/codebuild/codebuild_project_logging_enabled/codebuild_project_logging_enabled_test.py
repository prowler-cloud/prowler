from unittest.mock import patch

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_EU_WEST_1, set_mocked_aws_provider


class Test_codebuild_project_logging_enabled:
    @mock_aws
    def test_no_projects(self):
        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled import (
                codebuild_project_logging_enabled,
            )

            check = codebuild_project_logging_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_project_cloudwatch_logging_enabled(self):
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)

        project_name = "test-project-logging-enabled"

        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "S3",
                "location": "test-bucket",
            },
            artifacts={
                "type": "NO_ARTIFACTS",
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole="arn:aws:iam::123456789012:role/service-role/codebuild-role",
            logsConfig={
                "cloudWatchLogs": {
                    "status": "ENABLED",
                    "groupName": "cw-test-group",
                }
            },
            tags=[
                {"key": "Name", "value": "test"},
            ],
        )["project"]["arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled import (
                codebuild_project_logging_enabled,
            )

            check = codebuild_project_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} has CloudWatch logging enabled in log group cw-test-group."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == [{"key": "Name", "value": "test"}]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_s3_logging_enabled(self):
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)

        project_name = "test-project-logging-enabled"

        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "S3",
                "location": "test-bucket",
            },
            artifacts={
                "type": "NO_ARTIFACTS",
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole="arn:aws:iam::123456789012:role/service-role/codebuild-role",
            logsConfig={
                "s3Logs": {
                    "status": "ENABLED",
                    "location": "s3://test-bucket/logs",
                }
            },
            tags=[
                {"key": "Name", "value": "test"},
            ],
        )["project"]["arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled import (
                codebuild_project_logging_enabled,
            )

            check = codebuild_project_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} has S3 logging enabled in bucket s3://test-bucket/logs."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == [{"key": "Name", "value": "test"}]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_both_logging_enabled(self):
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)

        project_name = "test-project-logging-enabled"

        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "S3",
                "location": "test-bucket",
            },
            artifacts={
                "type": "NO_ARTIFACTS",
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole="arn:aws:iam::123456789012:role/service-role/codebuild-role",
            logsConfig={
                "cloudWatchLogs": {
                    "status": "ENABLED",
                    "groupName": "cw-test-group",
                },
                "s3Logs": {
                    "status": "ENABLED",
                    "location": "s3://test-bucket/logs",
                },
            },
            tags=[
                {"key": "Name", "value": "test"},
            ],
        )["project"]["arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled import (
                codebuild_project_logging_enabled,
            )

            check = codebuild_project_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} has enabled CloudWartch logs in log group cw-test-group and S3 logs in bucket s3://test-bucket/logs."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == [{"key": "Name", "value": "test"}]
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_aws
    def test_project_logging_disabled(self):
        codebuild_client = client("codebuild", region_name=AWS_REGION_EU_WEST_1)

        project_name = "test-project-logging-disabled"

        project_arn = codebuild_client.create_project(
            name=project_name,
            source={
                "type": "S3",
                "location": "test-bucket",
            },
            artifacts={
                "type": "NO_ARTIFACTS",
            },
            environment={
                "type": "LINUX_CONTAINER",
                "image": "aws/codebuild/standard:4.0",
                "computeType": "BUILD_GENERAL1_SMALL",
                "environmentVariables": [],
            },
            serviceRole="arn:aws:iam::123456789012:role/service-role/codebuild-role",
            logsConfig={
                "cloudWatchLogs": {
                    "status": "DISABLED",
                }
            },
            tags=[
                {"key": "Name", "value": "test"},
            ],
        )["project"]["arn"]

        aws_provider = set_mocked_aws_provider([AWS_REGION_EU_WEST_1])

        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        with patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_logging_enabled.codebuild_project_logging_enabled import (
                codebuild_project_logging_enabled,
            )

            check = codebuild_project_logging_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"CodeBuild project {project_name} does not have logging enabled."
            )
            assert result[0].resource_id == project_name
            assert result[0].resource_arn == project_arn
            assert result[0].resource_tags == [{"key": "Name", "value": "test"}]
            assert result[0].region == AWS_REGION_EU_WEST_1
