from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.lib.threats.demo_signature import DEMO_PUBLISHER, with_demo
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

CHECK = "prowler.providers.aws.services.ec2.ec2_instance_emerging_threat_image.ec2_instance_emerging_threat_image"
DEMOOS_OWNER = DEMO_PUBLISHER
MOTO_AMI = "ami-12c6146b"

make_api_call = botocore.client.BaseClient._make_api_call


def _describe_images_returning(image):
    """Let moto run EC2, but answer the AMI lookup with a third-party image."""

    def fake(self, operation_name, kwarg):
        if operation_name == "DescribeImages":
            if kwarg.get("Owners") == ["self"]:
                return {"Images": []}
            if image and MOTO_AMI in kwarg.get("ImageIds", []):
                return {"Images": [{"ImageId": MOTO_AMI, **image}]}
            return {"Images": []}
        return make_api_call(self, operation_name, kwarg)

    return fake


DEMOOS_TINY = {
    "Name": "demoos-3.22.2-x86_64-uefi-tiny-r0",
    "OwnerId": DEMOOS_OWNER,
    "Public": True,
}
DEMOOS_CLOUDINIT = {
    "Name": "demoos-3.22.2-x86_64-uefi-cloudinit-r0",
    "OwnerId": DEMOOS_OWNER,
    "Public": True,
}

DEMO_SIGNATURE = {
    "id": "demo-vendor-appliance",
    "title": "Demo appliance remote code execution",
    "cves": ["CVE-2026-0002"],
    "severity": "high",
    "summary": "Demo.",
    "images": [
        {
            "cloud": "aws",
            "publishers": ["444455556666"],
            "name_regex": r"^vendor-appliance-(?P<version>\d+\.\d+)$",
            "version_max": "7.1",
        }
    ],
    "exposure": {"protocol": "tcp", "port": 443},
    "credential_required": False,
    "impact": "Code execution on the appliance.",
    "remediation": "Upgrade to 7.2.",
}


def _run(audit_config=None, open_ssh=False, open_ports=()):
    """Create one instance with moto and run the check against it."""
    ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)
    sg_id = ec2.create_security_group(GroupName="web", Description="web")["GroupId"]
    for port in (22,) * open_ssh + tuple(open_ports):
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": port,
                    "ToPort": port,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )
    instance_id = ec2.run_instances(
        ImageId=MOTO_AMI, MinCount=1, MaxCount=1, SecurityGroupIds=[sg_id]
    )["Instances"][0]["InstanceId"]

    from prowler.providers.aws.services.ec2.ec2_service import EC2
    from prowler.providers.aws.services.vpc.vpc_service import VPC

    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1], audit_config=with_demo(audit_config)
    )
    with (
        mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ),
        mock.patch(f"{CHECK}.ec2_client", new=EC2(aws_provider)),
        mock.patch(f"{CHECK}.vpc_client", new=VPC(aws_provider)),
    ):
        from prowler.providers.aws.services.ec2.ec2_instance_emerging_threat_image.ec2_instance_emerging_threat_image import (
            ec2_instance_emerging_threat_image,
        )

        return instance_id, ec2_instance_emerging_threat_image().execute()


class Test_ec2_instance_emerging_threat_image:
    @mock_aws
    def test_no_instances(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(f"{CHECK}.ec2_client", new=EC2(aws_provider)),
            mock.patch(f"{CHECK}.vpc_client", new=VPC(aws_provider)),
        ):
            from prowler.providers.aws.services.ec2.ec2_instance_emerging_threat_image.ec2_instance_emerging_threat_image import (
                ec2_instance_emerging_threat_image,
            )

            assert ec2_instance_emerging_threat_image().execute() == []

    @mock_aws
    def test_demoos_tiny_cloud_with_open_ssh_fails(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            instance_id, result = _run(open_ssh=True)

        assert len(result) == 1
        finding = result[0]
        assert finding.status == "FAIL"
        assert finding.resource_id == instance_id
        assert finding.check_metadata.Severity == "critical"
        assert "CVE-2026-0101" in finding.status_extended
        assert "TCP 22 open to the internet" in finding.status_extended
        [threat] = finding.raw["threats"]
        assert threat["id"] == "demo-ssh-bypass"
        assert threat["provenance"] == "publisher"
        assert threat["exposed_to_internet"] is True
        assert threat["credential_required"] is False

    @mock_aws
    def test_demoos_tiny_cloud_without_exposure_still_fails(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            _, result = _run(open_ssh=False)

        assert result[0].status == "FAIL"
        assert result[0].raw["threats"][0]["exposed_to_internet"] is False

    @mock_aws
    def test_demoos_cloud_init_passes(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_CLOUDINIT),
        ):
            _, result = _run(open_ssh=True)

        assert result[0].status == "PASS"
        assert result[0].raw == {}
        assert "no known emerging threat" in result[0].status_extended

    @mock_aws
    def test_unresolved_ami_passes_with_reason(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(None),
        ):
            _, result = _run()

        assert result[0].status == "PASS"
        assert "could not be resolved" in result[0].status_extended

    @mock_aws
    def test_signature_from_scan_configuration(self):
        vendor_image = {
            "Name": "vendor-appliance-7.0",
            "OwnerId": "444455556666",
            "Public": True,
        }
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(vendor_image),
        ):
            _, result = _run(audit_config={"threat_signatures": [DEMO_SIGNATURE]})

        assert result[0].status == "FAIL"
        assert result[0].check_metadata.Severity == "high"
        assert [t["id"] for t in result[0].raw["threats"]] == ["demo-vendor-appliance"]
        assert result[0].raw["threats"][0]["exposed_to_internet"] is False

    @mock_aws
    def test_any_listed_port_open_counts_and_is_named(self):
        vendor_image = {
            "Name": "vendor-appliance-7.0",
            "OwnerId": "444455556666",
            "Public": True,
        }
        signature = {**DEMO_SIGNATURE, "exposure": {"ports": [443, 8443]}}
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(vendor_image),
        ):
            _, result = _run(
                audit_config={"threat_signatures": [signature]}, open_ports=(8443,)
            )

        [threat] = result[0].raw["threats"]
        assert threat["exposed_to_internet"] is True
        assert threat["exposure_port"] == 8443
        assert threat["exposure_ports"] == [443, 8443]
        assert "TCP 8443 open to the internet" in result[0].status_extended

    @mock_aws
    def test_severity_override_is_the_enum_the_outputs_read(self):
        # CSV, HTML and Jira outputs read Severity.value.
        from prowler.lib.check.models import Severity

        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            _, result = _run(open_ssh=True)

        assert result[0].check_metadata.Severity is Severity.critical
        assert result[0].check_metadata.Severity.value == "critical"
