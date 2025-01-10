from unittest import mock

from prowler.providers.aws.services.directconnect.directconnect_service import (
    Connection,
)
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, AWS_REGION_EU_WEST_1


class Test_directconnect_connection_redundancy:
    def test_no_conn(self):
        dx_client = mock.MagicMock
        dx_client.connections = {}
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_connection_redundancy.directconnect_connection_redundancy import (
                directconnect_connection_redundancy,
            )

            check = directconnect_connection_redundancy()
            result = check.execute()

            assert len(result) == 0

    def test_single_connection(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.audited_account_arn = (
            f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}"
        )
        dx_client._get_connection_arn_template = (
            lambda x: f"arn:aws:directconnect:{x}:{AWS_ACCOUNT_NUMBER}:connection"
        )
        dx_client.region = AWS_REGION_EU_WEST_1
        dx_client.connections = {}
        dx_client.connections = {
            "conn-test": Connection(
                id="conn-test",
                name="vif-id",
                location="Ashburn",
                region="eu-west-1",
            )
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ), mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect._get_connection_arn_template",
            return_value=f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection",
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_connection_redundancy.directconnect_connection_redundancy import (
                directconnect_connection_redundancy,
            )

            check = directconnect_connection_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is only one Direct Connect connection."
            )
            assert result[0].resource_id == "unknown"
            assert (
                result[0].resource_arn
                == f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_multiple_connections_single_location(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.audited_account_arn = (
            f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}"
        )
        dx_client._get_connection_arn_template = (
            lambda x: f"arn:aws:directconnect:{x}:{AWS_ACCOUNT_NUMBER}:connection"
        )
        dx_client.region = AWS_REGION_EU_WEST_1
        dx_client.connections = {}
        dx_client.connections = {
            "conn-test": Connection(
                id="conn-test",
                name="vif-id",
                location="Ashburn",
                region="eu-west-1",
            ),
            "conn-2": Connection(
                id="conn-2",
                name="vif-ids",
                location="Ashburn",
                region="eu-west-1",
            ),
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ), mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect._get_connection_arn_template",
            return_value=f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection",
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_connection_redundancy.directconnect_connection_redundancy import (
                directconnect_connection_redundancy,
            )

            check = directconnect_connection_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "There is only one location Ashburn used by all the Direct Connect connections."
            )
            assert result[0].resource_id == "unknown"
            assert (
                result[0].resource_arn
                == f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1

    def test_multiple_connections_multiple_locations(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.audited_account_arn = (
            f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}"
        )
        dx_client._get_connection_arn_template = (
            lambda x: f"arn:aws:directconnect:{x}:{AWS_ACCOUNT_NUMBER}:connection"
        )
        dx_client.region = AWS_REGION_EU_WEST_1
        dx_client.connections = {}
        dx_client.connections = {
            "conn-test": Connection(
                id="conn-test",
                name="vif-id",
                location="Ashburn",
                region="eu-west-1",
            ),
            "conn-2": Connection(
                id="conn-2",
                name="vif-ids",
                location="Loudon",
                region="eu-west-1",
            ),
        }
        with mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect",
            new=dx_client,
        ), mock.patch(
            "prowler.providers.aws.services.directconnect.directconnect_service.DirectConnect._get_connection_arn_template",
            return_value=f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection",
        ):
            # Test Check
            from prowler.providers.aws.services.directconnect.directconnect_connection_redundancy.directconnect_connection_redundancy import (
                directconnect_connection_redundancy,
            )

            check = directconnect_connection_redundancy()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "There are 2 Direct Connect connections across 2 locations."
            )
            assert result[0].resource_id == "unknown"
            assert (
                result[0].resource_arn
                == f"arn:aws:directconnect:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:connection"
            )
            assert result[0].region == AWS_REGION_EU_WEST_1
