from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"
AWS_ACCOUNT_NUMBER_2 = "111122223333"
AWS_ACCOUNT_ARN_2 = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER_2}:root"


class Test_vpc_endpoint_services_allowed_principals_trust_boundaries:
    @mock_aws
    def test_no_vpc_endpoint_services(self):
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 0

    @mock_aws
    def test_vpc_endpoint_service_without_allowed_principals(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint_id = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )["ServiceConfiguration"]["ServiceId"]

        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"VPC Endpoint Service {endpoint_id} has no allowed principals."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_endpoint_service_with_allowed_principal_account_arn(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint_id = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )["ServiceConfiguration"]["ServiceId"]

        # Add allowed principals
        ec2_client.modify_vpc_endpoint_service_permissions(
            ServiceId=endpoint_id, AddAllowedPrincipals=[AWS_ACCOUNT_ARN]
        )

        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Found trusted account {AWS_ACCOUNT_NUMBER} in VPC Endpoint Service {endpoint_id}."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_endpoint_service_with_allowed_principal_account_number(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint_id = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )["ServiceConfiguration"]["ServiceId"]

        # Add allowed principals
        ec2_client.modify_vpc_endpoint_service_permissions(
            ServiceId=endpoint_id, AddAllowedPrincipals=[AWS_ACCOUNT_NUMBER]
        )

        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Found trusted account {AWS_ACCOUNT_NUMBER} in VPC Endpoint Service {endpoint_id}."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_endpoint_service_with_principal_not_allowed(self):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint_id = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )["ServiceConfiguration"]["ServiceId"]

        # Add allowed principals
        ec2_client.modify_vpc_endpoint_service_permissions(
            ServiceId=endpoint_id, AddAllowedPrincipals=[AWS_ACCOUNT_NUMBER_2]
        )

        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": []}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "FAIL"
                assert (
                    result[0].status_extended
                    == f"Found untrusted account {AWS_ACCOUNT_NUMBER_2} in VPC Endpoint Service {endpoint_id}."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_vpc_endpoint_service_with_principal_different_than_account_but_allowed_in_config(
        self,
    ):
        # Create VPC Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        elbv2_client = client("elbv2", region_name=AWS_REGION_US_EAST_1)

        vpc = ec2_client.create_vpc(
            CidrBlock="172.28.7.0/24", InstanceTenancy="default"
        )
        subnet = ec2_client.create_subnet(
            VpcId=vpc["Vpc"]["VpcId"],
            CidrBlock="172.28.7.192/26",
            AvailabilityZone=f"{AWS_REGION_US_EAST_1}a",
        )
        lb_name = "lb_vpce-test"
        lb_arn = elbv2_client.create_load_balancer(
            Name=lb_name,
            Subnets=[subnet["Subnet"]["SubnetId"]],
            Scheme="internal",
            Type="network",
        )["LoadBalancers"][0]["LoadBalancerArn"]

        endpoint_id = ec2_client.create_vpc_endpoint_service_configuration(
            NetworkLoadBalancerArns=[lb_arn]
        )["ServiceConfiguration"]["ServiceId"]

        # Add allowed principals
        ec2_client.modify_vpc_endpoint_service_permissions(
            ServiceId=endpoint_id, AddAllowedPrincipals=[AWS_ACCOUNT_NUMBER_2]
        )

        endpoint_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:vpc-endpoint-service/{endpoint_id}"

        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(audited_regions=[AWS_REGION_US_EAST_1])
        # Set config variable
        aws_provider._audit_config = {"trusted_account_ids": [AWS_ACCOUNT_NUMBER_2]}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_client",
                new=VPC(aws_provider),
            ):
                # Test Check
                from prowler.providers.aws.services.vpc.vpc_endpoint_services_allowed_principals_trust_boundaries.vpc_endpoint_services_allowed_principals_trust_boundaries import (
                    vpc_endpoint_services_allowed_principals_trust_boundaries,
                )

                check = vpc_endpoint_services_allowed_principals_trust_boundaries()
                result = check.execute()

                assert len(result) == 1
                assert result[0].status == "PASS"
                assert (
                    result[0].status_extended
                    == f"Found trusted account {AWS_ACCOUNT_NUMBER_2} in VPC Endpoint Service {endpoint_id}."
                )
                assert result[0].resource_id == endpoint_id
                assert result[0].resource_arn == endpoint_arn
                assert result[0].resource_tags == []
                assert result[0].region == AWS_REGION_US_EAST_1
