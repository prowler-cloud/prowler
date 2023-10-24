from unittest import mock

from boto3 import session

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.networkfirewall.networkfirewall_service import (
    Firewall,
)
from prowler.providers.aws.services.vpc.vpc_service import VPCs, VpcSubnet
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"
FIREWALL_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall/my-firewall"
FIREWALL_NAME = "my-firewall"
VPC_ID_PROTECTED = "vpc-12345678901234567"
VPC_ID_UNPROTECTED = "vpc-12345678901234568"
POLICY_ARN = "arn:aws:network-firewall:us-east-1:123456789012:firewall-policy/my-policy"


class Test_networkfirewall_in_all_vpc:
    # Mocked Audit Info
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
                region_name=AWS_REGION,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=AWS_REGION,
            credentials=None,
            assumed_role_info=None,
            audited_regions=None,
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )
        return audit_info

    def test_no_vpcs(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {}

        audit_info = self.set_mocked_audit_info()

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
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
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
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_PROTECTED: VPCs(
                id=VPC_ID_PROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
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
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = self.set_mocked_audit_info()

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
                    assert result[0].region == AWS_REGION
                    assert result[0].resource_id == VPC_ID_PROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
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
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = self.set_mocked_audit_info()

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
                    assert result[0].region == AWS_REGION
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_with_name_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="vpc_name",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
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
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = self.set_mocked_audit_info()

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
                    assert result[0].region == AWS_REGION
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"

    def test_vpcs_with_and_without_firewall(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
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
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
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
                        region=AWS_REGION,
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
                region=AWS_REGION,
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
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            ),
        }

        audit_info = self.set_mocked_audit_info()

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
                            assert r.region == AWS_REGION
                            assert r.resource_id == VPC_ID_PROTECTED
                            assert r.resource_tags == []
                            assert r.resource_arn == "arn_test"
                        if r.resource_id == VPC_ID_UNPROTECTED:
                            assert r.status == "FAIL"
                            assert (
                                r.status_extended
                                == f"VPC {VPC_ID_UNPROTECTED} does not have Network Firewall enabled."
                            )
                            assert r.region == AWS_REGION
                            assert r.resource_id == VPC_ID_UNPROTECTED
                            assert r.resource_tags == []
                            assert r.resource_arn == "arn_test"

    def test_vpcs_without_firewall_ignoring(self):
        networkfirewall_client = mock.MagicMock
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
                arn="arn_test",
                subnets=[
                    VpcSubnet(
                        id="subnet-123456789",
                        arn="arn_test",
                        default=False,
                        vpc_id=VPC_ID_UNPROTECTED,
                        cidr_block="192.168.0.0/24",
                        availability_zone="us-east-1a",
                        public=False,
                        nat_gateway=False,
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = self.set_mocked_audit_info()
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
        networkfirewall_client.audit_info = self.set_mocked_audit_info()
        networkfirewall_client.region = AWS_REGION
        networkfirewall_client.network_firewalls = []
        vpc_client = mock.MagicMock
        vpc_client.audit_info = self.set_mocked_audit_info()
        vpc_client.region = AWS_REGION
        vpc_client.vpcs = {
            VPC_ID_UNPROTECTED: VPCs(
                id=VPC_ID_UNPROTECTED,
                name="vpc_name",
                default=False,
                cidr_block="192.168.0.0/16",
                flow_log=False,
                region=AWS_REGION,
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
                        region=AWS_REGION,
                        tags=[],
                        mapPublicIpOnLaunch=False,
                    )
                ],
                tags=[],
            )
        }

        audit_info = self.set_mocked_audit_info()
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
                    assert result[0].region == AWS_REGION
                    assert result[0].resource_id == VPC_ID_UNPROTECTED
                    assert result[0].resource_tags == []
                    assert result[0].resource_arn == "arn_test"
