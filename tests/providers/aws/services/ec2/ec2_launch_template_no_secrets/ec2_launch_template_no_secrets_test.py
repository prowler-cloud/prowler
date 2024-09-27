from base64 import b64encode
from os import path
from pathlib import Path
from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from prowler.config.config import encoding_format_utf_8
from prowler.providers.aws.services.ec2.ec2_service import (
    LaunchTemplate,
    LaunchTemplateVersion,
    TemplateData,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

ACTUAL_DIRECTORY = Path(path.dirname(path.realpath(__file__)))
FIXTURES_DIR_NAME = "fixtures"

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 123,
                    "LaunchTemplateData": {
                        "UserData": b64encode(
                            "DB_PASSWORD=foobar123".encode(encoding_format_utf_8)
                        ).decode(encoding_format_utf_8),
                        "NetworkInterfaces": [{"AssociatePublicIpAddress": True}],
                    },
                }
            ]
        }
    elif operation_name == "DescribeLaunchTemplates":
        return {
            "LaunchTemplates": [
                {
                    "LaunchTemplateName": "tester1",
                    "LaunchTemplateId": "lt-1234567890",
                    "Tags": [
                        {"Key": "Name", "Value": "tester1"},
                    ],
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


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
                    "This is some user_data".encode(encoding_format_utf_8)
                ).decode(encoding_format_utf_8),
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
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_one_launch_template_with_secrets(self):
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
                == "Potential secret found in User Data for EC2 Launch Template tester1 in template versions: 123."
            )
            assert result[0].resource_id == "lt-1234567890"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == (
                "arn:aws:ec2:us-east-1:123456789012:launch-template/lt-1234567890"
            )
            assert result[0].resource_tags == [{"Key": "Name", "Value": "tester1"}]

    def test_one_launch_template_with_secrets_in_multiple_versions(self):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        launch_template_data = TemplateData(
            user_data=b64encode(secrets).decode(encoding_format_utf_8),
            associate_public_ip_address=True,
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=1,
                template_data=launch_template_data,
            ),
            LaunchTemplateVersion(
                version_number=2,
                template_data=launch_template_data,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=ec2_client,
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
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: 1, 2."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    def test_one_launch_template_with_secrets_in_single_version(self):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        launch_template_data_secrets = TemplateData(
            user_data=b64encode(secrets).decode(encoding_format_utf_8),
            associate_public_ip_address=True,
        )
        launch_template_data_no_secrets = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=True,
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=1,
                template_data=launch_template_data_secrets,
            ),
            LaunchTemplateVersion(
                version_number=2,
                template_data=launch_template_data_no_secrets,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=ec2_client,
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
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: 1."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    def test_one_launch_template_with_secrets_gzip(self):
        ec2_client = mock.MagicMock()
        launch_template_name = "tester"
        launch_template_id = "lt-1234567890"
        launch_template_arn = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
        )

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture.gz",
            "rb",
        )
        secrets = f.read()

        launch_template_data = TemplateData(
            user_data=b64encode(secrets).decode(encoding_format_utf_8),
            associate_public_ip_address=True,
        )

        launch_template_versions = [
            LaunchTemplateVersion(
                version_number=1,
                template_data=launch_template_data,
            ),
        ]

        launch_template = LaunchTemplate(
            name=launch_template_name,
            id=launch_template_id,
            arn=launch_template_arn,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_versions,
        )

        ec2_client.launch_templates = [launch_template]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=ec2_client,
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
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name} in template versions: 1."
            )
            assert result[0].resource_id == launch_template_id
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

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
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []

    @mock.patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
    def test_two_launch_templates_one_template_with_secrets(self):
        ec2_client = mock.MagicMock()
        launch_template_name1 = "tester-secrets"
        launch_template_name2 = "tester-no-secrets"
        launch_template_id1 = "lt-1234567890"
        launch_template_id2 = "lt-0987654321"
        launch_template_arn1 = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id1}"
        )
        launch_template_arn2 = (
            f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id2}"
        )

        f = open(
            f"{ACTUAL_DIRECTORY}/{FIXTURES_DIR_NAME}/fixture",
            "rb",
        )
        secrets = f.read()

        launch_template_data_secrets = TemplateData(
            user_data=b64encode(secrets).decode(encoding_format_utf_8),
            associate_public_ip_address=True,
        )
        launch_template_data_no_secrets = TemplateData(
            user_data=b64encode("sinsecretos".encode(encoding_format_utf_8)).decode(
                encoding_format_utf_8
            ),
            associate_public_ip_address=True,
        )

        launch_template_secrets_version = [
            LaunchTemplateVersion(
                version_number=1,
                template_data=launch_template_data_secrets,
            ),
        ]
        launch_template_no_secret_version = [
            LaunchTemplateVersion(
                version_number=2,
                template_data=launch_template_data_no_secrets,
            ),
        ]

        launch_template_secrets = LaunchTemplate(
            name=launch_template_name1,
            id=launch_template_id1,
            arn=launch_template_arn1,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_secrets_version,
        )
        launch_template_no_secrets = LaunchTemplate(
            name=launch_template_name2,
            id=launch_template_id2,
            arn=launch_template_arn2,
            region=AWS_REGION_US_EAST_1,
            versions=launch_template_no_secret_version,
        )

        ec2_client.launch_templates = [
            launch_template_secrets,
            launch_template_no_secrets,
        ]

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=ec2_client,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_launch_template_no_secrets.ec2_launch_template_no_secrets.ec2_client",
            new=ec2_client,
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
                == f"Potential secret found in User Data for EC2 Launch Template {launch_template_name1} in template versions: 1."
            )
            assert result[0].resource_id == launch_template_id1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id1}"
            )
            assert result[0].resource_tags == []

            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"No secrets found in User Data of any version for EC2 Launch Template {launch_template_name2}."
            )
            assert result[1].resource_id == launch_template_id2
            assert result[1].region == AWS_REGION_US_EAST_1
            assert result[1].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id2}"
            )
            assert result[1].resource_tags == []

    @mock_aws
    def test_one_launch_template_with_unicode_error(self):
        launch_template_name = "tester"
        invalid_utf8_bytes = b"\xc0\xaf"

        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.create_launch_template(
            LaunchTemplateName=launch_template_name,
            VersionDescription="Launch Template with secrets",
            LaunchTemplateData={
                "InstanceType": "t1.micro",
                "UserData": b64encode(invalid_utf8_bytes).decode(encoding_format_utf_8),
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
            assert result[0].resource_arn == (
                f"arn:aws:ec2:us-east-1:123456789012:launch-template/{launch_template_id}"
            )
            assert result[0].resource_tags == []
