from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider


class Test_ec2_transitgateway_auto_accept_vpc_attachments:
    @mock_aws
    def test_no_transit_gateways(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.transit_gateways = []

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments import (
                ec2_transitgateway_auto_accept_vpc_attachments,
            )

            check = ec2_transitgateway_auto_accept_vpc_attachments()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_transit_gateway_default_options(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        tgw = ec2_client.create_transit_gateway(
            Description="Test TGW with auto-accept enabled",
        )
        tgw_id = tgw["TransitGateway"]["TransitGatewayId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments import (
                ec2_transitgateway_auto_accept_vpc_attachments,
            )

            check = ec2_transitgateway_auto_accept_vpc_attachments()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Transit Gateway {tgw_id} in region {AWS_REGION_US_EAST_1} does not automatically accept shared VPC attachments."
            )
            assert result[0].resource_id == tgw_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_transit_gateway_autoaccept_enabled(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        tgw = ec2_client.create_transit_gateway(
            Description="Test TGW with auto-accept enabled",
            Options={
                "AutoAcceptSharedAttachments": "enable",
            },
        )
        tgw_id = tgw["TransitGateway"]["TransitGatewayId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments import (
                ec2_transitgateway_auto_accept_vpc_attachments,
            )

            check = ec2_transitgateway_auto_accept_vpc_attachments()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Transit Gateway {tgw_id} in region {AWS_REGION_US_EAST_1} is configured to automatically accept shared VPC attachments."
            )
            assert result[0].resource_id == tgw_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_transit_gateway_autoaccept_disabled(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        tgw = ec2_client.create_transit_gateway(
            Description="Test TGW with auto-accept disabled",
            Options={
                "AutoAcceptSharedAttachments": "disable",
            },
        )
        tgw_id = tgw["TransitGateway"]["TransitGatewayId"]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments import (
                ec2_transitgateway_auto_accept_vpc_attachments,
            )

            check = ec2_transitgateway_auto_accept_vpc_attachments()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Transit Gateway {tgw_id} in region {AWS_REGION_US_EAST_1} does not automatically accept shared VPC attachments."
            )
            assert result[0].resource_id == tgw_id
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_multiple_transit_gateways(self):
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)

        # Create TGW with auto-accept enabled
        tgw_with_auto_accept = ec2_client.create_transit_gateway(
            Description="TGW with auto-accept enabled",
            Options={
                "AutoAcceptSharedAttachments": "enable",
            },
        )
        tgw_with_auto_accept_id = tgw_with_auto_accept["TransitGateway"][
            "TransitGatewayId"
        ]

        # Create TGW with auto-accept disabled
        tgw_without_auto_accept = ec2_client.create_transit_gateway(
            Description="TGW with auto-accept disabled",
            Options={
                "AutoAcceptSharedAttachments": "disable",
            },
        )
        tgw_without_auto_accept_id = tgw_without_auto_accept["TransitGateway"][
            "TransitGatewayId"
        ]

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_transitgateway_auto_accept_vpc_attachments.ec2_transitgateway_auto_accept_vpc_attachments import (
                ec2_transitgateway_auto_accept_vpc_attachments,
            )

            check = ec2_transitgateway_auto_accept_vpc_attachments()
            result = check.execute()

            assert len(result) == 2

            # Check the TGW with auto-accept enabled
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Transit Gateway {tgw_with_auto_accept_id} in region {AWS_REGION_US_EAST_1} is configured to automatically accept shared VPC attachments."
            )
            assert result[0].resource_id == tgw_with_auto_accept_id
            assert result[0].region == AWS_REGION_US_EAST_1

            # Check the TGW with auto-accept disabled
            assert result[1].status == "PASS"
            assert (
                result[1].status_extended
                == f"Transit Gateway {tgw_without_auto_accept_id} in region {AWS_REGION_US_EAST_1} does not automatically accept shared VPC attachments."
            )
            assert result[1].resource_id == tgw_without_auto_accept_id
            assert result[1].region == AWS_REGION_US_EAST_1
