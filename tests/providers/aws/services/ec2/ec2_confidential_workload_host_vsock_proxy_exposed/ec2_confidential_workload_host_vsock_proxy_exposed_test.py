from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed"
    ".ec2_confidential_workload_host_vsock_proxy_exposed"
)


def _create_enclave_with_sg(sg_ingress):
    ec2c = client("ec2", region_name=AWS_REGION_US_EAST_1)
    vpc_id = ec2c.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    sg_id = ec2c.create_security_group(
        GroupName="enclave-sg",
        Description="enclave sg",
        VpcId=vpc_id,
    )["GroupId"]
    if sg_ingress:
        ec2c.authorize_security_group_ingress(GroupId=sg_id, IpPermissions=sg_ingress)
    ec2c.create_subnet(VpcId=vpc_id, CidrBlock="10.0.1.0/24")
    ec2r = resource("ec2", region_name=AWS_REGION_US_EAST_1)
    instance = ec2r.create_instances(
        ImageId=EXAMPLE_AMI_ID,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_id],
    )[0]
    return instance, sg_id


class Test_ec2_confidential_workload_host_vsock_proxy_exposed:
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            assert ec2_confidential_workload_host_vsock_proxy_exposed().execute() == []

    @mock_aws
    def test_no_vsock_ports_exposed_pass(self):
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_vsock_proxy_exposed().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance.id

    @mock_aws
    def test_vsock_port_5000_exposed_fail(self):
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5000,
                    "ToPort": 5000,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_vsock_proxy_exposed().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "5000" in result[0].status_extended
            assert "heuristic" in result[0].status_extended.lower()

    @mock_aws
    def test_custom_vsock_ports_via_audit_config(self):
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 12345,
                    "ToPort": 12345,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._audit_config = {"enclave_vsock_ports": [12345]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_vsock_proxy_exposed().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "12345" in result[0].status_extended

    @mock_aws
    def test_non_enclave_instance_skipped(self):
        _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5000,
                    "ToPort": 5000,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = False
            assert ec2_confidential_workload_host_vsock_proxy_exposed().execute() == []

    @mock_aws
    def test_ipv6_world_cidr_flags_vsock_port_fail(self):
        # Vsock proxy port 5000 exposed via ::/0 (IPv6) only. Must FAIL.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 5000,
                    "ToPort": 5000,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_vsock_proxy_exposed().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "5000" in result[0].status_extended

    @mock_aws
    def test_missing_security_group_reports_manual_not_pass(self):
        # If an SG referenced by the instance is not present in ec2_client
        # (e.g., collection failure), the check must emit MANUAL rather than
        # silently PASSing on incomplete SG visibility.
        _create_enclave_with_sg([])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        ec2_svc = EC2(aws_provider)
        ec2_svc.security_groups = {}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=ec2_svc) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_vsock_proxy_exposed.ec2_confidential_workload_host_vsock_proxy_exposed import (
                ec2_confidential_workload_host_vsock_proxy_exposed,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_vsock_proxy_exposed().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "cannot be fully verified" in result[0].status_extended
