from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

EXAMPLE_AMI_ID = "ami-12c6146b"

CHECK_MODULE = (
    "prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress"
    ".ec2_confidential_workload_host_unrestricted_ingress"
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


class Test_ec2_confidential_workload_host_unrestricted_ingress:
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            assert ec2_confidential_workload_host_unrestricted_ingress().execute() == []

    @mock_aws
    def test_only_allow_listed_ports_pass(self):
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance.id

    @mock_aws
    def test_non_allow_listed_port_open_fail(self):
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "8080" in result[0].status_extended

    @mock_aws
    def test_configurable_allow_list_overrides_default(self):
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ]
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        aws_provider._audit_config = {"enclave_sg_allow_ports": [8080]}

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK_MODULE}.ec2_client", new=EC2(aws_provider)) as ec2c,
        ):
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].resource_id == instance.id

    @mock_aws
    def test_non_enclave_instance_skipped(self):
        _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = False
            assert ec2_confidential_workload_host_unrestricted_ingress().execute() == []

    @mock_aws
    def test_wide_range_summarized_fail(self):
        # Rule opens TCP 1000-65535 to 0.0.0.0/0 (~64k non-allow-listed
        # ports). Should be reported as the "1000-65535" summary, never
        # as thousands of individual ports.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 1000,
                    "ToPort": 65535,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "1000-65535" in result[0].status_extended
            # Sanity: individual ports must not leak into the message.
            assert "1001, 1002" not in result[0].status_extended

    @mock_aws
    def test_medium_range_ports_listed_individually_fail(self):
        # 6 ports (8080-8085), below the 10-port summary threshold — must
        # list each port individually so operators see the exact set.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8085,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            for port in range(8080, 8086):
                assert str(port) in result[0].status_extended

    @mock_aws
    def test_all_protocol_rule_reported_as_all_fail(self):
        # IpProtocol=-1 opens every protocol/port. Fast-path must catch it
        # as "all" without expanding to 65k ports.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "-1",
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "all" in result[0].status_extended

    @mock_aws
    def test_ipv6_world_cidr_flagged_fail(self):
        # Only ::/0 (IPv6) is world-facing; no IpRanges. Must still FAIL.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "tcp",
                    "FromPort": 8080,
                    "ToPort": 8080,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "8080" in result[0].status_extended

    @mock_aws
    def test_udp_world_facing_non_allow_listed_port_fail(self):
        # UDP was silently ignored before; the check now must flag it.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "udp",
                    "FromPort": 12345,
                    "ToPort": 12345,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "12345" in result[0].status_extended

    @mock_aws
    def test_udp_world_facing_ipv6_non_allow_listed_port_fail(self):
        # UDP over ::/0 is equally reachable — must FAIL.
        instance, _ = _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "udp",
                    "FromPort": 5353,
                    "ToPort": 5353,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].resource_id == instance.id
            assert "5353" in result[0].status_extended

    @mock_aws
    def test_icmp_world_facing_not_flagged_pass(self):
        # ICMP is not TCP/UDP → not tracked. Rule allows ICMP world-wide;
        # the check should still PASS because we only track L4 traffic.
        _create_enclave_with_sg(
            [
                {
                    "IpProtocol": "icmp",
                    "FromPort": -1,
                    "ToPort": -1,
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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "PASS"

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
            from prowler.providers.aws.services.ec2.ec2_confidential_workload_host_unrestricted_ingress.ec2_confidential_workload_host_unrestricted_ingress import (
                ec2_confidential_workload_host_unrestricted_ingress,
            )

            ec2c.instances[0].enclaves_enabled = True
            result = ec2_confidential_workload_host_unrestricted_ingress().execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert "cannot be fully verified" in result[0].status_extended
