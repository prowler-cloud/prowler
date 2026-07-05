from unittest.mock import MagicMock, patch

from prowler.providers.aws.services.glue.glue_service import Connection
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, AWS_ACCOUNT_NUMBER


class Test_glue_data_catalogs_connection_no_secrets_in_properties:
    def test_glue_no_connections(self):
        glue_client = MagicMock
        glue_client.connections = []
        glue_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }

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
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_no_secrets_in_properties.glue_data_catalogs_connection_no_secrets_in_properties import (
                glue_data_catalogs_connection_no_secrets_in_properties,
            )

            check = glue_data_catalogs_connection_no_secrets_in_properties()
            result = check.execute()

            assert len(result) == 0

    def test_glue_connection_no_secrets(self):
        glue_client = MagicMock
        glue_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        connection_name = "test-connection"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"

        glue_client.connections = [
            Connection(
                name=connection_name,
                type="JDBC",
                properties={
                    "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/mydb"
                },
                region=AWS_REGION_US_EAST_1,
                arn=connection_arn,
                tags=[{"test": "test"}],
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
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_no_secrets_in_properties.glue_data_catalogs_connection_no_secrets_in_properties import (
                glue_data_catalogs_connection_no_secrets_in_properties,
            )

            check = glue_data_catalogs_connection_no_secrets_in_properties()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Glue connection {connection_name} properties."
            )
            assert result[0].resource_id == connection_name
            assert result[0].resource_arn == connection_arn

    def test_glue_connection_with_secrets(self):
        glue_client = MagicMock
        glue_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        connection_name = "test-connection"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"

        glue_client.connections = [
            Connection(
                name=connection_name,
                type="JDBC",
                properties={
                    "PASSWORD": "AKIAsupersecretkey1234",
                    "JDBC_CONNECTION_URL": "jdbc:mysql://example.com:3306/mydb",
                },
                region=AWS_REGION_US_EAST_1,
                arn=connection_arn,
                tags=[{"test": "test"}],
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
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_no_secrets_in_properties.glue_data_catalogs_connection_no_secrets_in_properties import (
                glue_data_catalogs_connection_no_secrets_in_properties,
            )

            check = glue_data_catalogs_connection_no_secrets_in_properties()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert "Potential secrets found" in result[0].status_extended
            assert connection_name in result[0].status_extended
            assert "PASSWORD" in result[0].status_extended
            assert result[0].resource_id == connection_name
            assert result[0].resource_arn == connection_arn

    def test_glue_connection_empty_properties(self):
        glue_client = MagicMock
        glue_client.audit_config = {
            "secrets_ignore_patterns": [],
            "secrets_validate": False,
        }
        connection_name = "test-connection"
        connection_arn = f"arn:aws:glue:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:connection/{connection_name}"

        glue_client.connections = [
            Connection(
                name=connection_name,
                type="JDBC",
                properties={},
                region=AWS_REGION_US_EAST_1,
                arn=connection_arn,
                tags=[{"test": "test"}],
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
            from prowler.providers.aws.services.glue.glue_data_catalogs_connection_no_secrets_in_properties.glue_data_catalogs_connection_no_secrets_in_properties import (
                glue_data_catalogs_connection_no_secrets_in_properties,
            )

            check = glue_data_catalogs_connection_no_secrets_in_properties()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"No secrets found in Glue connection {connection_name} properties."
            )
            assert result[0].resource_id == connection_name
            assert result[0].resource_arn == connection_arn
