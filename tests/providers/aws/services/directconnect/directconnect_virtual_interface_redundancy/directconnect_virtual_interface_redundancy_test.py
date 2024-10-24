from unittest import mock

from prowler.providers.aws.services.directconnect.directconnect_service import (
    DXGateway,
    VirtualGateway,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_directconnect_virtual_interface_redundancy:
    def test_no_vif(self):
        dx_client = mock.MagicMock
        dx_client.vgws = {}
        dx_client.dxgws = {}
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 0

    def test_single_vif_single_connection_vgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.vgws = {
            "vgw-test": VirtualGateway(
                id="vgw-test",
                vifs=["vif-id"],
                connections=["dx-conn"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is only one VIF for the virtual gateway vgw-test."
            )
            assert result[0].resource_id == "vgw-test"
            assert result[0].resource_arn == "vgw-test"
            assert result[0].region == AWS_REGION

    def test_multiple_vifs_single_connection_vgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.vgws = {
            "vgw-test": VirtualGateway(
                id="vgw-test",
                vifs=["vif-id", "vif-id2"],
                connections=["dx-conn"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are more than 1 VIFs for the virtual gateway vgw-test, but all the VIFs are on the same DX Connection."
            )
            assert result[0].resource_id == "vgw-test"
            assert result[0].resource_arn == "vgw-test"
            assert result[0].region == AWS_REGION

    def test_multiple_vifs_multiple_connections_vgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.vgws = {
            "vgw-test": VirtualGateway(
                id="vgw-test",
                vifs=["vif-id", "vif-id2"],
                connections=["dx-conn", "dx-conn2"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "There are more than 1 VIFs for the virtual gateway vgw-test, and the VIFs are on more than one DX connection."
            )
            assert result[0].resource_id == "vgw-test"
            assert result[0].resource_arn == "vgw-test"
            assert result[0].region == AWS_REGION

    def test_single_vif_single_connection_dxgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.dxgws = {
            "dx-test": DXGateway(
                id="dx-test",
                vifs=["vif-id"],
                connections=["dx-conn"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is only one VIF for the direct connect gateway dx-test."
            )
            assert result[0].resource_id == "dx-test"
            assert result[0].resource_arn == "dx-test"
            assert result[0].region == AWS_REGION

    def test_multiple_vifs_single_connection_dxgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.dxgws = {
            "dx-test": DXGateway(
                id="dx-test",
                vifs=["vif-id", "vif-id2"],
                connections=["dx-conn"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There are more than 1 VIFs for direct connect gateway dx-test, but all the VIFs are on the same DX Connection."
            )
            assert result[0].resource_id == "dx-test"
            assert result[0].resource_arn == "dx-test"
            assert result[0].region == AWS_REGION

    def test_multiple_vifs_multiple_connections_dxgw(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
        dx_client.vgws = {}
        dx_client.dxgws = {}
        dx_client.dxgws = {
            "dx-test": DXGateway(
                id="dx-test",
                vifs=["vif-id", "vif-id2"],
                connections=["dx-conn", "dx-conn2"],
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_virtual_interface_redundancy.directconnect_virtual_interface_redundancy import (
                directconnect_virtual_interface_redundancy,
            )

            check = directconnect_virtual_interface_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "There are more than 1 VIFs for the direct connect gateway dx-test, and the VIFs are on more than one DX connection."
            )
            assert result[0].resource_id == "dx-test"
            assert result[0].resource_arn == "dx-test"
            assert result[0].region == AWS_REGION
