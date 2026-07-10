from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated"
    ".ec2_enclave_parent_terminated"
)


def _mocked_provider(state, enclaves_enabled=True):
    ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
    ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)
    return state, enclaves_enabled


class Test_ec2_enclave_parent_terminated:
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
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated.ec2_enclave_parent_terminated import (
                ec2_enclave_parent_terminated,
            )

            assert ec2_enclave_parent_terminated().execute() == []

    @mock_aws
    def test_running_enclave_parent_pass(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated.ec2_enclave_parent_terminated import (
                ec2_enclave_parent_terminated,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "running"

            result = ec2_enclave_parent_terminated().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

    @mock_aws
    def test_stopped_enclave_parent_fail(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated.ec2_enclave_parent_terminated import (
                ec2_enclave_parent_terminated,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "stopped"

            result = ec2_enclave_parent_terminated().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "stopped" in result[0].status_extended

    @mock_aws
    def test_terminated_enclave_parent_fail(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated.ec2_enclave_parent_terminated import (
                ec2_enclave_parent_terminated,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "terminated"

            result = ec2_enclave_parent_terminated().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "terminated" in result[0].status_extended

    @mock_aws
    def test_non_enclave_instance_skipped(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as client,
        ):
            from prowler.providers.aws.services.ec2.ec2_enclave_parent_terminated.ec2_enclave_parent_terminated import (
                ec2_enclave_parent_terminated,
            )

            client.instances[0].enclaves_enabled = False
            client.instances[0].state = "stopped"

            assert ec2_enclave_parent_terminated().execute() == []
