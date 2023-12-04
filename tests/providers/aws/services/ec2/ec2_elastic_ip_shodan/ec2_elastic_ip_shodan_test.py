from unittest import mock

from boto3 import client
from moto import mock_ec2

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_elastic_ip_shodan:
    @mock_ec2
    def test_ec2_one_instances_no_public_ip(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", AWS_REGION_EU_WEST_1)
        # Create EC2 Instance
        ec2_client.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"shodan_api_key": ""}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan import (
                ec2_elastic_ip_shodan,
            )

            check = ec2_elastic_ip_shodan()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_one_unattached_eip(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", AWS_REGION_EU_WEST_1)
        # Create EC2 Instance
        ec2_client.allocate_address(Domain="vpc")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"shodan_api_key": ""}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan import (
                ec2_elastic_ip_shodan,
            )

            check = ec2_elastic_ip_shodan()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_one_attached_eip_no_shodan_api_key(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", AWS_REGION_EU_WEST_1)
        # Create EC2 Instance
        instance = ec2_client.run_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1
        )
        allocation = ec2_client.allocate_address(Domain="vpc")
        ec2_client.associate_address(
            AllocationId=allocation["AllocationId"],
            InstanceId=instance["Instances"][0]["InstanceId"],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"shodan_api_key": ""}
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan import (
                ec2_elastic_ip_shodan,
            )

            check = ec2_elastic_ip_shodan()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_one_attached_eip_shodan_api_key(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", AWS_REGION_EU_WEST_1)
        # Create EC2 Instance
        instance = ec2_client.run_instances(
            ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1
        )
        allocation = ec2_client.allocate_address(Domain="vpc")
        public_ip = allocation["PublicIp"]
        allocation_id = allocation["AllocationId"]

        ec2_client.associate_address(
            AllocationId=allocation["AllocationId"],
            InstanceId=instance["Instances"][0]["InstanceId"],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1], audit_config={"shodan_api_key": ""}
        )
        current_audit_info.audit_config = {"shodan_api_key": "XXXXXXX"}

        ports = ["22", "443"]
        isp = "test-isp"
        country = "france"

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan.ec2_client",
            new=EC2(current_audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan.shodan.Shodan.host",
            return_value={"ports": ports, "isp": isp, "country_name": country},
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_elastic_ip_shodan.ec2_elastic_ip_shodan import (
                ec2_elastic_ip_shodan,
            )

            check = ec2_elastic_ip_shodan()
            result = check.execute()

            assert len(result) == 1
            assert result[0].resource_id == public_ip
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elastic IP {public_ip} listed in Shodan with open ports {str(ports)} and ISP {isp} in {country}. More info at https://www.shodan.io/host/{public_ip}."
            )
