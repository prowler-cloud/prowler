from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, AWS_ACCOUNT_NUMBER, set_mocked_aws_provider

class Test_codebuild_project_no_plantext_credentials:
    @mock_aws
    def test_no_project(self):
        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
            result = check.execute()

            assert len(result) == 0

    # test there is project with no environment variables
    @mock_aws
    def test_project_with_no_envvar(self):
        from prowler.providers.aws.services.codebuild.codebuild_service import Codebuild

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        codebuild_client = client("codebuild", region_name=AWS_REGION_US_EAST_1)

        codebuild_client.create_project(
            name="SensitiveProject",
            source={
                'type': 'NO_SOURCE',
                'location': 'dummy_location'},
            artifacts={'type': 'NO_ARTIFACTS'},
            environment={
                'type': 'LINUX_CONTAINER',
                'image': 'aws/codebuild/standard:4.0',
                'computeType': 'BUILD_GENERAL1_SMALL',
                'environmentVariables': []
            },
            serviceRole='arn:aws:iam::123456789012:role/service-role/codebuild-test-service-role'
        )
        
        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials.codebuild_client",
            new=Codebuild(aws_provider),
        ):
            from prowler.providers.aws.services.codebuild.codebuild_project_no_plaintext_credentials.codebuild_project_no_plaintext_credentials import (
                codebuild_project_no_plaintext_credentials,
            )

            check = codebuild_project_no_plaintext_credentials()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"


    # test there is project with no plaintext credentials

    # test there is projecto with plaintext but not sensitive

    # test there is project with plaintext and sensitive