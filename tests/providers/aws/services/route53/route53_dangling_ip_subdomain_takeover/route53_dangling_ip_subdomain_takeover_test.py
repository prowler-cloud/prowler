from re import search
from unittest import mock

from boto3 import client, resource
from moto import mock_ec2, mock_route53

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_route53_dangling_ip_subdomain_takeover:
    @mock_ec2
    @mock_route53
    def test_no_hosted_zones(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 0

    @mock_ec2
    @mock_route53
    def test_hosted_zone_no_records(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)

        conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 0

    @mock_ec2
    @mock_route53
    def test_hosted_zone_private_record(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)

        zone_id = conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "foo.bar.testdns.aws.com",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "192.168.1.1"}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "is not a dangling IP",
                        result[0].status_extended,
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/192.168.1.1"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_ec2
    @mock_route53
    def test_hosted_zone_external_record(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)

        zone_id = conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "foo.bar.testdns.aws.com",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "17.5.7.3"}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "does not belong to AWS and it is not a dangling IP",
                        result[0].status_extended,
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_ec2
    @mock_route53
    def test_hosted_zone_dangling_public_record(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)

        zone_id = conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "foo.bar.testdns.aws.com",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "54.152.12.70"}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert search(
                        "is a dangling IP",
                        result[0].status_extended,
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/54.152.12.70"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_ec2
    @mock_route53
    def test_hosted_zone_eip_record(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)
        ec2 = client("ec2", region_name=AWS_REGION_EU_WEST_1)

        ec2.allocate_address(Domain="vpc", Address="17.5.7.3")

        zone_id = conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "foo.bar.testdns.aws.com",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "17.5.7.3"}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "is not a dangling IP",
                        result[0].status_extended,
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_ec2
    @mock_route53
    def test_hosted_zone_eni_record(self):
        conn = client("route53", region_name=AWS_REGION_EU_WEST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_EU_WEST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        eni_id = ec2.create_network_interface(SubnetId=subnet.id).id
        eip = ec2_client.allocate_address(Domain="vpc", Address="17.5.7.3")
        ec2_client.associate_address(
            NetworkInterfaceId=eni_id, AllocationId=eip["AllocationId"]
        )

        zone_id = conn.create_hosted_zone(
            Name="testdns.aws.com.", CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": "foo.bar.testdns.aws.com",
                            "Type": "A",
                            "ResourceRecords": [{"Value": "17.5.7.3"}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(audit_info),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(audit_info),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert search(
                        "is not a dangling IP",
                        result[0].status_extended,
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{audit_info.audited_partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )
