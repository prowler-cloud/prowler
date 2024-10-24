from unittest import mock

from prowler.providers.aws.services.directconnect.directconnect_service import (
    Connection,
)

AWS_REGION = "eu-west-1"
AWS_ACCOUNT_NUMBER = "123456789012"


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
        dx_client.region = AWS_REGION
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
                == "There is only one direct connect connection in eu-west-1."
            )
            assert result[0].resource_id == "Direct Connect Connection(s)"
            assert result[0].resource_arn == "Direct Connect Connection(s)"
            assert result[0].region == AWS_REGION

    def test_multiple_connections_single_location(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
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
                == "There is only one location Ashburn used by all the direct connect connections in eu-west-1."
            )
            assert result[0].resource_id == "Direct Connect Connection(s)"
            assert result[0].resource_arn == "Direct Connect Connection(s)"
            assert result[0].region == AWS_REGION

    def test_multiple_connections_multiple_locations(self):
        dx_client = mock.MagicMock
        dx_client.audited_account = AWS_ACCOUNT_NUMBER
        dx_client.region = AWS_REGION
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
                == "There are 2 direct connect connections, using 2 locations in eu-west-1."
            )
            assert result[0].resource_id == "Direct Connect Connection(s)"
            assert result[0].resource_arn == "Direct Connect Connection(s)"
            assert result[0].region == AWS_REGION
