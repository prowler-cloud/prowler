from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.glue.glue_service import Connection
from tests.providers.aws.utils import AWS_REGION_US_EAST_1


class Test_glue_database_connections_ssl_enabled:
    def test_glue_no_conns(self):
        glue_client = MagicMock
        glue_client.connections = []

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_database_connections_ssl_enabled.glue_database_connections_ssl_enabled import (
                glue_database_connections_ssl_enabled,
            )

            check = glue_database_connections_ssl_enabled()
            result = check.execute()

            assert len(result) == 0

    def test_glue_table_no_SSL(self):
        glue_client = MagicMock
        glue_client.connections = [
            Connection(
                name="test",
                type="JDBC",
                properties={
                    "CONNECTOR_TYPE": "Jdbc",
                    "JDBC_CONNECTION_URL": '[["default=test"],":"]',
                    "CONNECTOR_URL": "s3://bck-dev",
                    "CONNECTOR_CLASS_NAME": "test",
                },
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
                tags=[{"test": "test"}],
            )
        ]

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_database_connections_ssl_enabled.glue_database_connections_ssl_enabled import (
                glue_database_connections_ssl_enabled,
            )

            check = glue_database_connections_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == "Glue connection test has SSL connection disabled."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
            assert result[0].resource_tags == [{"test": "test"}]

    def test_glue_table_with_SSL(self):
        glue_client = MagicMock
        glue_client.connections = [
            Connection(
                name="test",
                type="JDBC",
                properties={
                    "CONNECTOR_TYPE": "Jdbc",
                    "JDBC_CONNECTION_URL": '[["default=test"],":"]',
                    "CONNECTOR_URL": "s3://bck-dev",
                    "CONNECTOR_CLASS_NAME": "test",
                    "JDBC_ENFORCE_SSL": "true",
                },
                region=AWS_REGION_US_EAST_1,
                arn="arn_test",
                tags=[{"test": "test"}],
            )
        ]

        with patch(
            "prowler.providers.aws.services.glue.glue_service.Glue",
            new=glue_client,
        ), patch(
            "prowler.providers.aws.services.glue.glue_client.glue_client",
            new=glue_client,
        ):
            # Test Check
            from prowler.providers.aws.services.glue.glue_database_connections_ssl_enabled.glue_database_connections_ssl_enabled import (
                glue_database_connections_ssl_enabled,
            )

            check = glue_database_connections_ssl_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == "Glue connection test has SSL connection enabled."
            )
            assert result[0].resource_id == "test"
            assert result[0].resource_arn == "arn_test"
            assert result[0].resource_tags == [{"test": "test"}]
