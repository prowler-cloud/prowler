from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running"
    ".ec2_confidential_workload_host_not_running"
)


class Test_ec2_confidential_workload_host_not_running:
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            assert ec2_confidential_workload_host_not_running().execute() == []

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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "running"

            result = ec2_confidential_workload_host_not_running().execute()
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "stopped"

            result = ec2_confidential_workload_host_not_running().execute()
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            client.instances[0].enclaves_enabled = True
            client.instances[0].state = "terminated"

            result = ec2_confidential_workload_host_not_running().execute()
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            client.instances[0].enclaves_enabled = False
            client.instances[0].state = "stopped"

            assert ec2_confidential_workload_host_not_running().execute() == []

    @mock_aws
    def test_stopping_state_pass_transient(self):
        # RFC v2.7: 'stopping' is a transient state, reported as PASS with note.
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].state = "stopping"

            result = ec2_confidential_workload_host_not_running().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "transient" in result[0].status_extended
            assert "stopping" in result[0].status_extended

    @mock_aws
    def test_pending_state_pass_transient(self):
        # RFC v2.7: 'pending' is a transient state, reported as PASS with note.
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].state = "pending"

            result = ec2_confidential_workload_host_not_running().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert "transient" in result[0].status_extended

    @mock_aws
    def test_shutting_down_state_flagged(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_not_running.ec2_confidential_workload_host_not_running import (
                ec2_confidential_workload_host_not_running,
            )

            ec2c.instances[0].enclaves_enabled = True
            ec2c.instances[0].state = "shutting-down"

            result = ec2_confidential_workload_host_not_running().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "shutting-down" in result[0].status_extended
