from unittest import mock

from boto3 import client, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

EXAMPLE_AMI_ID = "ami-12c6146b"
AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "eu-west-1"


class Test_ec2_elastic_ip_shodan:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
            audit_config={"shodan_api_key": ""},
        )

        return audit_info

    @mock_ec2
    def test_ec2_one_instances_no_public_ip(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", AWS_REGION)
        # Create EC2 Instance
        ec2_client.run_instances(ImageId=EXAMPLE_AMI_ID, MinCount=1, MaxCount=1)

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
        ec2_client = client("ec2", AWS_REGION)
        # Create EC2 Instance
        ec2_client.allocate_address(Domain="vpc")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
        ec2_client = client("ec2", AWS_REGION)
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

        current_audit_info = self.set_mocked_audit_info()

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
        ec2_client = client("ec2", AWS_REGION)
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

        current_audit_info = self.set_mocked_audit_info()
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
                == f"arn:aws:ec2:{AWS_REGION}:{AWS_ACCOUNT_NUMBER}:eip-allocation/{allocation_id}"
            )
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elastic IP {public_ip} listed in Shodan with open ports {str(ports)} and ISP {isp} in {country}. More info https://www.shodan.io/host/{public_ip}"
            )
