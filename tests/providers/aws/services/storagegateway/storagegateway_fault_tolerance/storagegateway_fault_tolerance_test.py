from unittest import mock

from prowler.providers.aws.services.storagegateway.storagegateway_service import Gateway
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_US_EAST_1

test_gateway = "sgw-12A3456B"
test_gateway_arn = f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{test_gateway}"


class Test_storagegateway_fault_tolerance:
    def test_no_storagegateway_gateway(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.gateways = []
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fault_tolerance.storagegateway_fault_tolerance import (
                storagegateway_fault_tolerance,
            )

            check = storagegateway_fault_tolerance()
            result = check.execute()
            assert len(result) == 0

    def test_gateway_on_ec2(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.gateways = []
        storagegateway_client.gateways.append(
            Gateway(
                id=test_gateway,
                arn=test_gateway_arn,
                name="test",
                gateway_type="fsx",
                region=AWS_REGION_US_EAST_1,
                environment="EC2",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fault_tolerance.storagegateway_fault_tolerance import (
                storagegateway_fault_tolerance,
            )

            check = storagegateway_fault_tolerance()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "StorageGateway Gateway test is hosted on AWS. Please ensure this gateway is not used for critical workloads."
            )
            assert result[0].resource_id == f"{test_gateway}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{test_gateway}"
            )

    def test_gateway_not_on_ec2(self):
        storagegateway_client = mock.MagicMock
        storagegateway_client.gateways = []
        storagegateway_client.gateways.append(
            Gateway(
                id=test_gateway,
                arn=test_gateway_arn,
                name="test",
                gateway_type="fsx",
                region=AWS_REGION_US_EAST_1,
                environment="VMWARE",
            )
        )
        with mock.patch(
            "prowler.providers.aws.services.storagegateway.storagegateway_service.StorageGateway",
            storagegateway_client,
        ):
            from prowler.providers.aws.services.storagegateway.storagegateway_fault_tolerance.storagegateway_fault_tolerance import (
                storagegateway_fault_tolerance,
            )

            check = storagegateway_fault_tolerance()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "StorageGateway Gateway test is not hosted on AWS."
            )
            assert result[0].resource_id == f"{test_gateway}"
            assert result[0].region == AWS_REGION_US_EAST_1
            assert (
                result[0].resource_arn
                == f"arn:aws:storagegateway:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:gateway/{test_gateway}"
            )
