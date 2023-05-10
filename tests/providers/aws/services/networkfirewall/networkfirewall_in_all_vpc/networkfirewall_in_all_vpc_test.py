from unittest import mock

from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    Firewall,
)
from prowler.providers.aws.services.vpc.vpc_service import VPCs, VpcSubnet

AWS_REGION = "us-east-1"
FIREWALL_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall"
FIREWALL_NAME = "my-firewall"
VPC_ID_PROTECTED = "vpc-12345678901234567"
VPC_ID_UNPROTECTED = "vpc-12345678901234568"
POLICY_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/my-policy"


class Test_networkfirewall_in_all_vpc:
    def test_no_vpcs(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {}
        with mock.patch(
            "prowler.providers.aws.services.networkfirewall.networkfirewall_service.NetworkFirewall",
            new=networkfirewall_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                new=vpc_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc import (
                    networkfirewall_in_all_vpc,
                )

                check = networkfirewall_in_all_vpc()
                result = check.execute()

                assert len(result) == 0

    def test_vpcs_with_firewall_all(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = [
            Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
            )
        ]
        vpc_client = mock.MagicMock
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_PROTECTED: VPCs(
                id=VPC_ID_PROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        default=False,
                        vpc_id=VPC_ID_PROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        region=AWS_REGION,
                        tags=[],
                    )
                ],
                tags=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.networkfirewall.networkfirewall_service.NetworkFirewall",
            new=networkfirewall_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                new=vpc_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc import (
                    networkfirewall_in_all_vpc,
                )

                check = networkfirewall_in_all_vpc()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC {VPC_ID_PROTECTED} has Network Firewall enabled."
                )
                assert result[0].region == AWS_REGION
                assert result[0].resource_id == VPC_ID_PROTECTED
                assert result[0].resource_tags == []
                assert result[0].resource_arn == ""

    def test_vpcs_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        region=AWS_REGION,
                        tags=[],
                    )
                ],
                tags=[],
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.networkfirewall.networkfirewall_service.NetworkFirewall",
            new=networkfirewall_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                new=vpc_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc import (
                    networkfirewall_in_all_vpc,
                )

                check = networkfirewall_in_all_vpc()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"VPC {VPC_ID_UNPROTECTED} does not have Network Firewall enabled."
                )
                assert result[0].region == AWS_REGION
                assert result[0].resource_id == VPC_ID_UNPROTECTED
                assert result[0].resource_tags == []
                assert result[0].resource_arn == ""

    def test_vpcs_with_and_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = [
            Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
            )
        ]
        vpc_client = mock.MagicMock
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        region=AWS_REGION,
                        tags=[],
                    )
                ],
                tags=[],
            ),
            VPC_ID_PROTECTED: VPCs(
                id=VPC_ID_PROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        default=False,
                        vpc_id=VPC_ID_PROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        region=AWS_REGION,
                        tags=[],
                    )
                ],
                tags=[],
            ),
        }
        with mock.patch(
            "prowler.providers.aws.services.networkfirewall.networkfirewall_service.NetworkFirewall",
            new=networkfirewall_client,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_service.VPC",
                new=vpc_client,
            ):
                # Test Check
                from prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc import (
                    networkfirewall_in_all_vpc,
                )

                check = networkfirewall_in_all_vpc()
                result = check.execute()

                assert len(result) == 2
                for r in result:
                    if r.resource_id == VPC_ID_PROTECTED:
                        assert r.status == "PASS"
                        assert (
                            r.status_extended
                            == f"VPC {VPC_ID_PROTECTED} has Network Firewall enabled."
                        )
                        assert r.region == AWS_REGION
                        assert r.resource_id == VPC_ID_PROTECTED
                        assert r.resource_tags == []
                        assert r.resource_arn == ""
                    if r.resource_id == VPC_ID_UNPROTECTED:
                        assert r.status == "FAIL"
                        assert (
                            r.status_extended
                            == f"VPC {VPC_ID_UNPROTECTED} does not have Network Firewall enabled."
                        )
                        assert r.region == AWS_REGION
                        assert r.resource_id == VPC_ID_UNPROTECTED
                        assert r.resource_tags == []
                        assert r.resource_arn == ""
