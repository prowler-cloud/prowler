from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.glue.glue_service import Connection
from tests.providers.aws.utils import AWS_REGION_US_EAST_1

CONNECTION_ARN = (
    f"arn:aws:glue:{AWS_REGION_US_EAST_1}:123456789012:connection/test-connection"
)


class Test_glue_connection_no_secrets:
    def test_glue_no_connections(self):
        glue_client = MagicMock
        glue_client.connections = []
        glue_client.audit_config = {}

        with (
            patch(
                "prowler.providers.aws.services.glue.glue_service.Glue",
                new=glue_client,
            ),
            patch(
                "prowler.providers.aws.services.glue.glue_client.glue_client",
                new=glue_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                glue_connection_no_secrets,
            )

            check = glue_connection_no_secrets()
            result = check.execute()

            assert len(result) == 0

    def test_glue_connection_no_secrets(self):
        glue_client = MagicMock
        glue_client.audit_config = {}
        glue_client.connections = [
            Connection(
                name="test-connection",
                arn=CONNECTION_ARN,
                type="JDBC",
                properties={
                    "JDBC_CONNECTION_URL": "jdbc:mysql://db.example.com:3306/mydb",
                    "USERNAME": "admin",
                },
                region=AWS_REGION_US_EAST_1,
                tags=[{"key_test": "value_test"}],
            )
        ]

        with (
            patch(
                "prowler.providers.aws.services.glue.glue_service.Glue",
                new=glue_client,
            ),
            patch(
                "prowler.providers.aws.services.glue.glue_client.glue_client",
                new=glue_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                glue_connection_no_secrets,
            )

            check = glue_connection_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "No secrets found in Glue connection test-connection properties."
            )
            assert result[0].resource_id == "test-connection"
            assert result[0].resource_arn == CONNECTION_ARN
            assert result[0].resource_tags == [{"key_test": "value_test"}]

    def test_glue_connection_with_secrets(self):
        glue_client = MagicMock
        glue_client.audit_config = {}
        glue_client.connections = [
            Connection(
                name="test-connection",
                arn=CONNECTION_ARN,
                type="JDBC",
                properties={
                    "JDBC_CONNECTION_URL": "jdbc:mysql://db.example.com:3306/mydb",
                    "PASSWORD": "AKIAsupersecretkey1234",
                },
                region=AWS_REGION_US_EAST_1,
                tags=[{"key_test": "value_test"}],
            )
        ]

        with (
            patch(
                "prowler.providers.aws.services.glue.glue_service.Glue",
                new=glue_client,
            ),
            patch(
                "prowler.providers.aws.services.glue.glue_client.glue_client",
                new=glue_client,
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_connection_no_secrets.glue_connection_no_secrets import (
                glue_connection_no_secrets,
            )

            check = glue_connection_no_secrets()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secrets found" in result[0].status_extended
            assert "test-connection" in result[0].status_extended
            assert "PASSWORD" in result[0].status_extended
            assert "AKIAsupersecretkey1234" not in result[0].status_extended
            assert result[0].resource_id == "test-connection"
            assert result[0].resource_arn == CONNECTION_ARN
            assert result[0].resource_tags == [{"key_test": "value_test"}]
