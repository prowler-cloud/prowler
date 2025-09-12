from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 1,
                    "LaunchTemplateData": {
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpTokens": "required",
                        }
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_empty(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 1,
                    "LaunchTemplateData": {
                        "MetadataOptions": {
                            "HttpEndpoint": "",
                            "HttpTokens": "required",
                        }
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


def mock_make_api_call_not_required(self, operation_name, kwarg):
    if operation_name == "DescribeLaunchTemplateVersions":
        return {
            "LaunchTemplateVersions": [
                {
                    "VersionNumber": 1,
                    "LaunchTemplateData": {
                        "MetadataOptions": {
                            "HttpEndpoint": "enabled",
                            "HttpTokens": "optional",
                        }
                    },
                }
            ]
        }
    return make_api_call(self, operation_name, kwarg)


class Test_ec2_launch_template_imdsv2_required:
    @mock_aws
    def test_no_launch_templates(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.launch_templates = []

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required import (
                ec2_launch_template_imdsv2_required,
            )

            check = ec2_launch_template_imdsv2_required()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_launch_template_imdsv2_required(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call", new=mock_make_api_call
        ):
            launch_template_name = "test-imdsv2-required"
            ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
            ec2_client.create_launch_template(
                LaunchTemplateName=launch_template_name,
                VersionDescription="Launch Template with IMDSv2 required",
                LaunchTemplateData={
                    "InstanceType": "t1.micro",
                    "MetadataOptions": {
                        "HttpEndpoint": "enabled",
                        "HttpTokens": "required",
                    },
                },
            )

            launch_template_id = ec2_client.describe_launch_templates(
                LaunchTemplateNames=[launch_template_name]
            )["LaunchTemplates"][0]["LaunchTemplateId"]

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required.ec2_client",
                    new=EC2(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required import (
                    ec2_launch_template_imdsv2_required,
                )

                check = ec2_launch_template_imdsv2_required()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"EC2 Launch Template {launch_template_name} has IMDSv2 enabled and required in the following versions: 1."
                )
                assert result[0].resource_id == launch_template_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_launch_template_imdsv2_required_empty(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_empty,
        ):
            ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
            launch_template_name = "test-imdsv2-required-empty"
            ec2_client.create_launch_template(
                LaunchTemplateName=launch_template_name,
                VersionDescription="Launch Template with IMDSv2 required",
                LaunchTemplateData={
                    "InstanceType": "t1.micro",
                    "MetadataOptions": {
                        "HttpEndpoint": "",
                        "HttpTokens": "required",
                    },
                },
            )

            launch_template_id = ec2_client.describe_launch_templates(
                LaunchTemplateNames=[launch_template_name]
            )["LaunchTemplates"][0]["LaunchTemplateId"]

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required.ec2_client",
                    new=EC2(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required import (
                    ec2_launch_template_imdsv2_required,
                )

                check = ec2_launch_template_imdsv2_required()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"EC2 Launch Template {launch_template_name} has metadata service disabled in the following versions: 1."
                )
                assert result[0].resource_id == launch_template_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
                )
                assert result[0].resource_tags == []

    @mock_aws
    def test_launch_template_imdsv2_not_required(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=mock_make_api_call_not_required,
        ):
            ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
            launch_template_name = "test-imdsv2-not-required"
            ec2_client.create_launch_template(
                LaunchTemplateName=launch_template_name,
                VersionDescription="Launch Template without IMDSv2 required",
                LaunchTemplateData={
                    "InstanceType": "t1.micro",
                    "MetadataOptions": {
                        "HttpEndpoint": "enabled",
                        "HttpTokens": "optional",
                    },
                },
            )

            launch_template_id = ec2_client.describe_launch_templates(
                LaunchTemplateNames=[launch_template_name]
            )["LaunchTemplates"][0]["LaunchTemplateId"]

            from prowler.providers.aws.services.ec2.ec2_service import EC2

            aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

            with (
                mock.patch(
                    "prowler.providers.common.provider.Provider.get_global_provider",
                    return_value=aws_provider,
                ),
                mock.patch(
                    "prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required.ec2_client",
                    new=EC2(aws_provider),
                ),
            ):
                # Test Check
                from prowler.providers.aws.services.ec2.ec2_launch_template_imdsv2_required.ec2_launch_template_imdsv2_required import (
                    ec2_launch_template_imdsv2_required,
                )

                check = ec2_launch_template_imdsv2_required()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"EC2 Launch Template {launch_template_name} has IMDSv2 disabled or not required in the following versions: 1."
                )
                assert result[0].resource_id == launch_template_id
                assert result[0].region == AWS_REGION_US_EAST_1
                assert (
                    result[0].resource_arn
                    == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:123456789012:launch-template/{launch_template_id}"
                )
                assert result[0].resource_tags == []
