from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced"
    ".ec2_confidential_workload_host_imdsv2_not_enforced"
)


class Test_ec2_confidential_workload_host_imdsv2_not_enforced:
    @mock_aws
    def test_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced.ec2_confidential_workload_host_imdsv2_not_enforced import (
                ec2_confidential_workload_host_imdsv2_not_enforced,
            )

            assert ec2_confidential_workload_host_imdsv2_not_enforced().execute() == []

    @mock_aws
    def test_non_enclave_instance_skipped(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced.ec2_confidential_workload_host_imdsv2_not_enforced import (
                ec2_confidential_workload_host_imdsv2_not_enforced,
            )

            client.instances[0].enclaves_enabled = False
            assert ec2_confidential_workload_host_imdsv2_not_enforced().execute() == []

    @mock_aws
    def test_enclave_parent_imdsv2_enforced_pass(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={"HttpTokens": "required", "HttpEndpoint": "enabled"},
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced.ec2_confidential_workload_host_imdsv2_not_enforced import (
                ec2_confidential_workload_host_imdsv2_not_enforced,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].http_tokens = "required"

            result = ec2_confidential_workload_host_imdsv2_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance.id
            assert "enforces IMDSv2" in result[0].status_extended

    @mock_aws
    def test_enclave_parent_imdsv1_fail(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        instance = ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
        )[0]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced.ec2_confidential_workload_host_imdsv2_not_enforced import (
                ec2_confidential_workload_host_imdsv2_not_enforced,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].http_tokens = "optional"

            result = ec2_confidential_workload_host_imdsv2_not_enforced().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "does not enforce IMDSv2" in result[0].status_extended

    @mock_aws
    def test_terminated_instance_skipped(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(
            ImageId=EXAMPLE_AMI_ID,
            MinCount=1,
            MaxCount=1,
            MetadataOptions={"HttpTokens": "optional", "HttpEndpoint": "enabled"},
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_imdsv2_not_enforced.ec2_confidential_workload_host_imdsv2_not_enforced import (
                ec2_confidential_workload_host_imdsv2_not_enforced,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "terminated"

            assert ec2_confidential_workload_host_imdsv2_not_enforced().execute() == []
