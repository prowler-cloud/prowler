from unittest import mock

import botocore
from boto3 import client
from moto import mock_aws

from tests.lib.threats.demo_signature import DEMO_PUBLISHER, with_demo
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

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


def _describe_images_denied(self, operation_name, kwarg):
    """Let moto run EC2, but refuse the AMI lookup as a missing permission would."""
    if operation_name == "DescribeImages":
        if kwarg.get("Owners") == ["self"]:
            return {"Images": []}
        raise botocore.exceptions.ClientError(
            {"Error": {"Code": "UnauthorizedOperation", "Message": "denied"}},
            operation_name,
        )
    return make_api_call(self, operation_name, kwarg)


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


def _public_subnet(ec2) -> tuple:
    """``(vpc id, subnet id)`` of a subnet whose default route is an internet gateway."""
    vpc_id = ec2.create_vpc(CidrBlock="10.0.0.0/16")["Vpc"]["VpcId"]
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.0.0.0/24")["Subnet"][
        "SubnetId"
    ]
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    route_table_id = ec2.create_route_table(VpcId=vpc_id)["RouteTable"]["RouteTableId"]
    ec2.create_route(
        RouteTableId=route_table_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id
    )
    ec2.associate_route_table(RouteTableId=route_table_id, SubnetId=subnet_id)
    return vpc_id, subnet_id


def _run(
    audit_config=None,
    open_ssh=False,
    open_ports=(),
    public=False,
    only_instance=False,
    terminate=False,
):
    """Create one instance with moto and run the check against it.

    ``public`` puts it on a public IP in a public subnet; ``only_instance``
    filters the scan to the instance's ARN, as ``--resource-arn`` does.
    """
    ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)
    vpc_id, subnet_id = _public_subnet(ec2) if public else (None, None)
    sg_id = ec2.create_security_group(
        GroupName="web", Description="web", **({"VpcId": vpc_id} if vpc_id else {})
    )["GroupId"]
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
        ImageId=MOTO_AMI,
        MinCount=1,
        MaxCount=1,
        SecurityGroupIds=[sg_id],
        **({"SubnetId": subnet_id} if subnet_id else {}),
    )["Instances"][0]["InstanceId"]
    if terminate:
        ec2.terminate_instances(InstanceIds=[instance_id])

    from prowler.providers.aws.services.ec2.ec2_service import EC2
    from prowler.providers.aws.services.vpc.vpc_service import VPC

    aws_provider = set_mocked_aws_provider(
        [AWS_REGION_US_EAST_1], audit_config=with_demo(audit_config)
    )
    if only_instance:
        aws_provider._audit_resources = [
            f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:instance/{instance_id}"
        ]
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
    def test_no_instances_with_signatures_configured(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.vpc.vpc_service import VPC

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_US_EAST_1], audit_config=with_demo()
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
        # The check sees the launch image, not what was installed since.
        assert finding.status_extended.startswith(
            f"EC2 Instance {instance_id} was launched from AMI {MOTO_AMI}"
        )
        assert "patched in place" in finding.status_extended
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
    def test_public_route_is_reported_even_with_the_port_closed(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            _, result = _run(open_ssh=False, public=True)

        [threat] = result[0].raw["threats"]
        assert threat["exposed_to_internet"] is False
        assert threat["public_route"] is True
        # The signature lists the closed port as a control that breaks the chain.
        assert threat["mitigations_observed"] == ["port_not_exposed"]

    @mock_aws
    def test_open_port_on_a_public_route(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            _, result = _run(open_ssh=True, public=True)

        [threat] = result[0].raw["threats"]
        assert threat["exposed_to_internet"] is True
        assert threat["public_route"] is True
        assert threat["mitigations_observed"] == []

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
    def test_failed_ami_lookup_is_manual_not_pass(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_denied,
        ):
            instance_id, result = _run()

        assert result[0].status == "MANUAL"
        assert result[0].resource_id == instance_id
        assert "ec2:DescribeImages" in result[0].status_extended
        assert result[0].raw == {}

    @mock_aws
    def test_amazon_ami_is_matched_when_the_scan_is_filtered_to_the_instance(
        self,
    ):
        amazon_owned = {**DEMOOS_TINY, "ImageOwnerAlias": "amazon"}
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(amazon_owned),
        ):
            instance_id, result = _run(only_instance=True)

        assert [(f.resource_id, f.status) for f in result] == [(instance_id, "FAIL")]
        assert result[0].raw["threats"][0]["id"] == "demo-ssh-bypass"

    @mock_aws
    def test_unloaded_security_groups_leave_exposure_unknown(self):
        # A scan filtered to the instance ARN does not load its security groups,
        # so the check cannot say whether the port is open.
        amazon_owned = {**DEMOOS_TINY, "ImageOwnerAlias": "amazon"}
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(amazon_owned),
        ):
            _, result = _run(open_ssh=True, only_instance=True)

        [threat] = result[0].raw["threats"]
        assert threat["exposed_to_internet"] is None
        assert threat["mitigations_observed"] == []
        assert "open to the internet" not in result[0].status_extended

    @mock_aws
    def test_ami_description_is_matched_too(self):
        described = {
            "Name": "golden-base-2026",
            "Description": "demoos-3.22.2-x86_64-uefi-tiny-r0",
            "OwnerId": DEMOOS_OWNER,
            "Public": True,
        }
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(described),
        ):
            _, result = _run()

        assert result[0].status == "FAIL"
        assert result[0].raw["threats"][0]["image"] == (
            f"{MOTO_AMI} (demoos-3.22.2-x86_64-uefi-tiny-r0)"
        )

    @mock_aws
    def test_terminated_instances_are_skipped(self):
        with mock.patch(
            "botocore.client.BaseClient._make_api_call",
            new=_describe_images_returning(DEMOOS_TINY),
        ):
            _, result = _run(terminate=True)

        assert result == []

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
