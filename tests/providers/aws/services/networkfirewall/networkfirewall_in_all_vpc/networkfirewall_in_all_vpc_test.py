from unittest import mock

from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    Firewall,
)
from prowler.providers.aws.services.vpc.vpc_service import VPCs, VpcSubnet
from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

FIREWALL_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall"
FIREWALL_NAME = "my-firewall"
VPC_ID_PROTECTED = "vpc-12345678901234567"
VPC_ID_UNPROTECTED = "vpc-12345678901234568"
POLICY_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/my-policy"


class Test_networkfirewall_in_all_vpc:
    def test_no_vpcs(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {}

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = [
            Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_EU_WEST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
            )
        ]
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_PROTECTED: VPCs(
                id=VPC_ID_PROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="",
                        default=False,
                        vpc_id=VPC_ID_PROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
                    assert result[0].region == AWS_REGION_EU_WEST_1
                    assert result[0].resource_id == VPC_ID_PROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
                    assert result[0].region == AWS_REGION_EU_WEST_1
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_with_name_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = []

        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="vpc_name",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
                        == "VPC vpc_name does not have Network Firewall enabled."
                    )
                    assert result[0].region == AWS_REGION_EU_WEST_1
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_with_and_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = [
            Firewall(
                arn=FIREWALL_ARN,
                name=FIREWALL_NAME,
                region=AWS_REGION_EU_WEST_1,
                policy_arn=POLICY_ARN,
                vpc_id=VPC_ID_PROTECTED,
                tags=[],
                encryption_type="CUSTOMER_KMS",
            )
        ]
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            ),
            VPC_ID_PROTECTED: VPCs(
                id=VPC_ID_PROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="",
                        default=False,
                        vpc_id=VPC_ID_PROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            ),
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
                            assert r.region == AWS_REGION_EU_WEST_1
                            assert r.resource_id == VPC_ID_PROTECTED
                            assert r.resource_tags == []
                            assert r.resource_arn == "arn_test"
                        if r.resource_id == VPC_ID_UNPROTECTED:
                            assert r.status == "FAIL"
                            assert (
                                r.status_extended
                                == f"VPC {VPC_ID_UNPROTECTED} does not have Network Firewall enabled."
                            )
                            assert r.region == AWS_REGION_EU_WEST_1
                            assert r.resource_id == VPC_ID_UNPROTECTED
                            assert r.resource_tags == []
                            assert r.resource_arn == "arn_test"

    def test_vpcs_without_firewall_ignoring(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                name="vpc_name",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        name="",
                        arn="arn_test",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
                ):
                    # Test Check
                    from prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc import (
                        networkfirewall_in_all_vpc,
                    )

                    check = networkfirewall_in_all_vpc()
                    result = check.execute()

                    assert len(result) == 0

    def test_vpcs_without_firewall_ignoring_vpc_in_use(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1]
        )
        networkfirewall_client.region = AWS_REGION_EU_WEST_1
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.region = AWS_REGION_EU_WEST_1
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="vpc_name",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION_EU_WEST_1,
                arn="arn_test",
                in_use=True,
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        name="subnet_name",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION_EU_WEST_1,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        vpc_client.audit_info.ignore_unused_services = True

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.vpc_client",
                new=vpc_client,
            ):
                with mock.patch(
                    "prowler.providers.aws.services.networkfirewall.networkfirewall_in_all_vpc.networkfirewall_in_all_vpc.networkfirewall_client",
                    new=networkfirewall_client,
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
                        == "VPC vpc_name does not have Network Firewall enabled."
                    )
                    assert result[0].region == AWS_REGION_EU_WEST_1
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"
