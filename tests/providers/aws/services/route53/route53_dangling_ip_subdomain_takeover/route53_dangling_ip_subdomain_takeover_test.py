from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

HOSTED_ZONE_NAME = "testdns.aws.com."


class Test_route53_dangling_ip_subdomain_takeover:
    @mock_aws
    def test_no_hosted_zones(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 0

    @mock_aws
    def test_hosted_zone_no_records(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)

        conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 0

    @mock_aws
    def test_hosted_zone_private_record(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)

        zone_id = conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        record_set_name = "foo.bar.testdns.aws.com."
        record_ip = "192.168.1.1"
        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_set_name,
                            "Type": "A",
                            "ResourceRecords": [{"Value": record_ip}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Route53 record {record_ip} (name: {record_set_name}) in Hosted Zone {HOSTED_ZONE_NAME} is not a dangling IP."
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/192.168.1.1"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_aws
    def test_hosted_zone_external_record(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)

        zone_id = conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        record_set_name = "foo.bar.testdns.aws.com."
        record_ip = "17.5.7.3"
        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_set_name,
                            "Type": "A",
                            "ResourceRecords": [{"Value": record_ip}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Route53 record {record_ip} (name: {record_set_name}) in Hosted Zone {HOSTED_ZONE_NAME} does not belong to AWS and it is not a dangling IP."
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_aws
    def test_hosted_zone_dangling_public_record(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)

        zone_id = conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        record_set_name = "foo.bar.testdns.aws.com."
        record_ip = "54.152.12.70"
        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_set_name,
                            "Type": "A",
                            "ResourceRecords": [{"Value": record_ip}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "FAIL"
                    assert (
                        result[0].status_extended
                        == f"Route53 record {record_ip} (name: {record_set_name}) in Hosted Zone {HOSTED_ZONE_NAME} is a dangling IP which can lead to a subdomain takeover attack."
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/54.152.12.70"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_aws
    def test_hosted_zone_eip_record(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)
        ec2 = client("ec2", region_name=AWS_REGION_US_EAST_1)

        address = "17.5.7.3"
        ec2.allocate_address(Domain="vpc", Address=address)

        zone_id = conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        record_set_name = "foo.bar.testdns.aws.com."
        record_ip = address
        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_set_name,
                            "Type": "A",
                            "ResourceRecords": [{"Value": record_ip}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Route53 record {record_ip} (name: {record_set_name}) in Hosted Zone {HOSTED_ZONE_NAME} is not a dangling IP."
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )

    @mock_aws
    def test_hosted_zone_eni_record(self):
        conn = client("route53", region_name=AWS_REGION_US_EAST_1)
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        subnet = ec2.create_subnet(VpcId=vpc.id, CidrBlock="10.0.0.0/18")
        eni_id = ec2.create_network_interface(SubnetId=subnet.id).id
        address = "17.5.7.3"
        eip = ec2_client.allocate_address(Domain="vpc", Address=address)
        ec2_client.associate_address(
            NetworkInterfaceId=eni_id, AllocationId=eip["AllocationId"]
        )

        zone_id = conn.create_hosted_zone(
            Name=HOSTED_ZONE_NAME, CallerReference=str(hash("foo"))
        )["HostedZone"]["Id"]

        record_set_name = "foo.bar.testdns.aws.com."
        record_ip = address
        conn.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                "Changes": [
                    {
                        "Action": "CREATE",
                        "ResourceRecordSet": {
                            "Name": record_set_name,
                            "Type": "A",
                            "ResourceRecords": [{"Value": record_ip}],
                        },
                    }
                ]
            },
        )
        from prowler.providers.aws.services.ec2.ec2_service import EC2
        from prowler.providers.aws.services.route53.route53_service import Route53

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ):
            with mock.patch(
                "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.route53_client",
                new=Route53(aws_provider),
            ):
                with mock.patch(
                    "prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover.ec2_client",
                    new=EC2(aws_provider),
                ):
                    # Test Check
                    from prowler.providers.aws.services.route53.route53_dangling_ip_subdomain_takeover.route53_dangling_ip_subdomain_takeover import (
                        route53_dangling_ip_subdomain_takeover,
                    )

                    check = route53_dangling_ip_subdomain_takeover()
                    result = check.execute()

                    assert len(result) == 1
                    assert result[0].status == "PASS"
                    assert (
                        result[0].status_extended
                        == f"Route53 record {record_ip} (name: {record_set_name}) in Hosted Zone {HOSTED_ZONE_NAME} is not a dangling IP."
                    )
                    assert (
                        result[0].resource_id
                        == zone_id.replace("/hostedzone/", "") + "/17.5.7.3"
                    )
                    assert (
                        result[0].resource_arn
                        == f"arn:{aws_provider.identity.partition}:route53:::hostedzone/{zone_id.replace('/hostedzone/', '')}"
                    )
