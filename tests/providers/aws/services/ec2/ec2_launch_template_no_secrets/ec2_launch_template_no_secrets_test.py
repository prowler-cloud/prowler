from base64 import b64encode
from os import path
from pathlib import Path
from unittest import mock

from boto3 import client
from moto import mock_aws

from prowler.config.config import enconding_format_utf_8
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"


class Test_ec2_launch_template_no_secrets:
    @mock_aws
    def test_no_launch_templates(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.launch_templates = []

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_one_launch_template_with_no_secrets(self):
        # Include launch_template to check
        launch_template_name = "tester"
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template without secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(
                    "This is some user_data".encode(enconding_format_utf_8)
                ).decode(enconding_format_utf_8),
            },
        )

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in User Data of any version for EC2 Launch Template {launch_template_name}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_template_with_secrets(self):
        launch_template_name = "tester"

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        launch_template_version = ec2_client.describe_launch_template_versions(
            LaunchTemplateName=launch_template_name
        )["LaunchTemplateVersions"][0]["VersionNumber"]

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: {launch_template_version}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_template_with_secrets_in_multiple_versions(self):
        launch_template_name = "tester"

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        ec2_client.create_launch_template_version(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Second Launch Template version with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        launch_template_version_numbers = [
            str(v["VersionNumber"])
            for v in ec2_client.describe_launch_template_versions(
                LaunchTemplateName=launch_template_name
            )["LaunchTemplateVersions"]
        ]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: {', '.join(launch_template_version_numbers)}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_template_with_secrets_in_single_version(self):
        launch_template_name = "tester"

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        version_with_secrets = ec2_client.describe_launch_template_versions(
            LaunchTemplateName=launch_template_name,
        )["LaunchTemplateVersions"][0]["VersionNumber"]

        ec2_client.create_launch_template_version(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Second Launch Template version without secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: {version_with_secrets}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_template_with_secrets_gzip(self):
        launch_template_name = "tester"

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture.gz",
            "rb",
        )
        secrets = f.read()

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        launch_template_version = ec2_client.describe_launch_template_versions(
            LaunchTemplateName=launch_template_name
        )["LaunchTemplateVersions"][0]["VersionNumber"]

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: {launch_template_version}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_one_launch_template_without_user_data(self):
        launch_template_name = "tester"

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template without user data",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
            },
        )

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in User Data of any version for EC2 Launch Template {launch_template_name}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_two_launch_templates_one_template_with_secrets(self):
        launch_template_name_with_secrets = "tester1"
        launch_template_name_without_secrets = "tester2"

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name_with_secrets,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(secrets).decode(enconding_format_utf_8),
            },
        )

        launch_template_id = ec2_client.describe_launch_templates()["LaunchTemplates"][
            0
        ]["LaunchTemplateId"]
        template_version_with_secrets = ec2_client.describe_launch_template_versions(
            LaunchTemplateName=launch_template_name_with_secrets
        )["LaunchTemplateVersions"][0]["VersionNumber"]

        # Create second launch template with no secret in UserData (NOT a new version)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name_without_secrets,
            VersionDescription="Launch Template without secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(b"Test").decode(enconding_format_utf_8),
            },
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets import (
                ec2_launch_template_no_secrets,
            )

            check = ec2_launch_template_no_secrets()
            result = check.execute()

            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name_with_secrets} in template versions: {template_version_with_secrets}."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1

            assert result[1].status == "PASS"
